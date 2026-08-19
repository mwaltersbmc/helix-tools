# HITT backlog

Future improvements captured from reviews — not scheduled for immediate work.

---

## `discoverIngressControllerDetails` — fallback chain and error handling

Status: **backlog**

Function: `discoverIngressControllerDetails` in `hitt.sh` (~6685).

### Problem summary

| Issue | Detail |
|-------|--------|
| **Comment vs code** | Header documents: `$1` → `INGRESS_CLASS_NAME` → `HP_INGRESS_CLASS` → `nginx`. Implementation only does: `$1` → `nginx`. |
| **Empty config** | When `HP_INGRESS_CLASS` is empty, callers pass `""`; function defaults to `nginx` instead of using config or failing clearly. |
| **Stale globals on failure** | `INGRESS_CLASS_NAME` is set before IngressClass lookup; on error 266 it may remain `nginx` while controller fields stay empty/unknown. |
| **Return code ignored** | `gatherInfo()` and `info ingress` do not check return value; report continues with partial or misleading ingress data. |
| **Display gap** | `printIngressControllerDetails` shows `HP_INGRESS_CLASS` (config) only, not `INGRESS_CLASS_NAME` (what discovery actually used). `writeInfoJson` exports both. |

### Current impact

- **Low** on typical installs: both call sites pass `"${HP_INGRESS_CLASS}"` explicitly when config is populated.
- **Medium** when `INGRESS_CLASS` is missing from configmap or `helixingress-master` has no `ingressClassName` — silent fallback to `nginx` may error or match the wrong controller.

### Proposed fix (when picked up)

1. Implement the documented fallback chain inside the function:

   ```bash
   ic_name="${1:-}"
   [[ -z "${ic_name}" ]] && ic_name="${INGRESS_CLASS_NAME:-}"
   [[ -z "${ic_name}" ]] && ic_name="${HP_INGRESS_CLASS:-}"
   [[ -z "${ic_name}" ]] && ic_name="nginx"
   ```

2. Optionally fail fast (or log a warning) when all sources are empty instead of defaulting to `nginx`.

3. On lookup failure (errors 266/267), clear or set `INGRESS_CLASS_NAME` to `unknown` so `info.json` is not polluted.

4. Restore a “Resolved IngressClass name” line in `printIngressControllerDetails` (config vs resolved).

5. Check return code in `gatherInfo` / `info ingress`, or log when discovery fails under `QUIET=1`.

### Test plan

- Cluster with valid `INGRESS_CLASS` in configmap — discovery matches expected controller.
- Configmap with `INGRESS_CLASS` missing/empty — verify behaviour after fix (warning or explicit failure, not silent `nginx`).
- `bash hitt.sh -m info` and `bash hitt.sh -m info ingress` — human report and `info.json` ingress fields consistent.
- No-arg call `discoverIngressControllerDetails` (if exposed or tested in isolation) — uses `HP_INGRESS_CLASS` when set.
