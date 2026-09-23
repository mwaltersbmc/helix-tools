# HITT backlog

Future improvements captured from reviews — not scheduled for immediate work.

---

## `use-util-pod` — temporary troubleshooting pod

Status: **backlog** — see [TODO-use-util-pod.md](TODO-use-util-pod.md) for the reference Pod YAML and implementation checklist (util pod with `lp0lz` image for in-cluster `curl`, `CURL_POD`, probe checks).

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
- `bash hitt.sh -i` and `bash hitt.sh -i ingress` — human report and `info.json` ingress fields consistent.
- No-arg call `discoverIngressControllerDetails` (if exposed or tested in isolation) — uses `HP_INGRESS_CLASS` when set.

---

## `get gsi` / `getARGSI` — validation and REST error handling

Status: **backlog**

Utility mode: `parseUtilGet` → `gsi` branch; `getARGSI()` (~3241). Review item **#5** (Sep 2026).

### Problem summary

| Issue | Detail |
|-------|--------|
| **Non-numeric GSI id** | `jq --argjson id "${GSI_ID}"` fails when the user passes a constant name instead of a number. |
| **Silent REST failures** | `getARGSI` uses `curl -sk` with no HTTP status check; HTML/error bodies still piped to `jq -r '.value'` → empty value and a misleading success line. |
| **`get gsi list` + QUIET** | Branch sets `QUIET=1` then `exit` without resetting `QUIET` (low risk; inconsistent with other branches). |

### Proposed fix (when picked up)

1. **Validate id** — After `list`, require `^[0-9]+$` (same pattern as `get fields` / `schemaId`). Clear error pointing at `get gsi list`.
2. **Optional name → id** — If arg matches `^AR_SERVER_INFO_`, resolve numeric id from `AR_SERVER_INFO_JSON` before the REST call.
3. **Name lookup in jq** — Use `--arg id` + string compare (or `tonumber` after bash validation), not `--argjson`, for `GSI_NAME`.
4. **Harden `getARGSI`** — Mirror `runARRESTSQL`: temp file, `%{http_code}`, `jq -e` on body, `logError` on non-2xx / empty / invalid JSON; surface `.value` only on success.
5. **`gsi` branch flow** — Handle `list` before `QUIET=1`; reset `QUIET=0` before `exit 0` on list; validate id → `initISAdminREST` → `getARGSI` → display.
6. **Docs** — One line in `README-utility-mode.md` / usage: numeric id or (if implemented) constant name; API path `systemconfiguration/{id}`.

### Test plan

- `bash hitt.sh -u "get gsi list"` — exits cleanly, no stray status noise with `-q` elsewhere in same script path.
- `bash hitt.sh -u "get gsi 89"` — known id returns a value when IS is up.
- `bash hitt.sh -u "get gsi not-a-number"` — friendly error, no jq stack trace.
- Invalid id or 401/404 — explicit HITT error, not `GSI value for 'UNKNOWN (99)' is ''`.
- Optional: `bash hitt.sh -u "get gsi AR_SERVER_INFO_SERVER_NAME"` if name resolution is added.

---

## Remove unused functions in `hitt.sh`

Status: **backlog**

Static analysis (Sep 2026): **12** functions in `hitt.sh` are defined but never called (function name appears only at the definition). Remove in a dedicated cleanup pass when convenient — no functional change expected.

| Line | Function | Notes |
|------|----------|--------|
| 429 | `generateRandom` | Random hex helper; no references |
| 1218 | `checkPlatformSSL` | Replaced by `validateCacertsFile HP` |
| 1751 | `runARDriver` | Wrapper for driver exec; callers use inline exec |
| 1787 | `getDeployedISSecret` | Sibling of `getDeployedISSTS` (which is used) |
| 1792 | `getDeployedISVersion` | Version read done elsewhere |
| 2135 | `setVarsFromPipelineJSON` | Incomplete; superseded by `getPipelineValues` |
| 2385 | `checkBlank` | Callers use `isBlank` directly |
| 3052 | `checkISFTSElasticHost` | Superseded by `checkFTSElasticSettings` / `checkIsValidElastic` |
| 3400 | `checkSRDBSettings` | Stub (`echo TODO` only) |
| 3813 | `checkJenkinsCredentials` | Marked `# NOT USED` in source |
| 4370 | `xgetPipelineDefaults` | Marked `# Old version` |
| 6832 | `URLEncode` | Re-check before delete — used by `get group` / `get user`; `scripts/imagemgr.sh` has its own copy |

### When picked up

1. Delete the functions above (and any now-orphaned comments).
2. Re-run a static unused-function scan on `hitt.sh` to confirm zero dead definitions.
3. `bash -n hitt/hitt.sh` and a quick smoke run (`bash hitt.sh -i helix` or `-m pre-is` if available).
