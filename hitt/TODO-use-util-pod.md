# TODO: `use-util-pod` — temporary troubleshooting pod

Status: **backlog**

Create (or reuse) a short-lived utility pod in the IS namespace so HITT can run cluster-network troubleshooting commands — especially HTTP probes for `check liveness` / `check readiness` — without relying on a platform pod that may not have `curl`.

---

## Problem summary

| Issue | Detail |
|-------|--------|
| **No guaranteed curl pod** | Platform pods may not expose `curl`; exec into target pods is heavy and may lack tools. |
| **Probe checks need cluster network** | `httpGet` probes target pod IP / service DNS from inside the cluster; HITT runs outside and needs an in-cluster runner. |
| **Ephemeral vs long-lived** | A dedicated util pod can be created on demand, run one command, and exit (`restartPolicy: Never`). |

---

## Reference pod manifest

Apply in the target IS namespace (e.g. `mrw-01-is`). Replace the example `curl` target IP/port/path with the probe URL from `parseProbeJSON`.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: curl
spec:
  imagePullSecrets:
  - name: helixregsecret
  containers:
  - image: docker.io/bmchelix/lp0lz:26301-v838-ade-infra-clients-alpine
    name: curl
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
    command:
    - /bin/bash
    - -c
    - |
      curl -sk http://100.64.1.87:46100/arapi/liveness
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
  dnsPolicy: ClusterFirst
  restartPolicy: Never
```

---

## Proposed HITT behaviour

1. **`use-util-pod`** (or internal helper) — ensure a util pod exists in `IS_NAMESPACE`:
   - Create from template above if none running.
   - Reuse existing `curl` pod if still `Running` / `Pending`.
   - Set **`CURL_POD`** (pod name) for callers.
2. **Run command** — `kubectl exec` into util pod with probe URL + headers from `parseProbeJSON`.
3. **Cleanup** — optional: delete pod after command, or leave for repeated checks in the same session.

---

## Checklist

- [ ] Add `ensureUtilPod` / `useUtilPod` helper in `hitt.sh`
- [ ] Parameterise image, pull secret, and resource limits (configmap or constants)
- [ ] Wire `checkPodProbe` to exec curl from util pod using parsed `scheme` / `host` / `port` / `path` / `headers`
- [ ] Wait for pod `Ready` before exec; clear errors if image pull or scheduling fails
- [ ] Document in `README-utility-mode.md` and `showUtilHelp`
- [ ] Add use case to `docs/hitt/use-cases.json`

---

## Test plan

- `bash hitt.sh -u "check readiness <pod>"` — HTTP response from util pod matches kubelet probe target.
- `bash hitt.sh -u "check liveness <platform-pod>"` — numeric port not in `ports[]` (e.g. `46200`) still works.
- Namespace without `helixregsecret` — fail with actionable message.
- Second invocation reuses running util pod when appropriate.
