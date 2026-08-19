# TODO: `-k get` / `-k build` — reliable pipeline trigger

Status: **proposal / in discussion** (not fully implemented)

This document captures the problem analysis, agreed direction, and remaining work from the get/build design discussion.

---

## Problem summary

HITT pipeline mode (`-k get` / `-k build`) was originally oriented toward **queue a draft run → Rebuild in Jenkins UI**. Triggering a **real** build via the API exposes three gaps:

| Gap | Symptom | Root cause |
|-----|---------|------------|
| **Empty values dropped on `get`** | Params like `PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS` missing from saved JSON | `getJenkinsPipelineValues()` strips keys where `value == ""` |
| **Missing params on `build`** | `MissingPropertyException: No such property: GIT_REPO_DIR` | Jenkins API builds only bind **submitted** parameters; job defaults are **not** applied for omitted keys |
| **In-cluster param stripping** | Values present in JSON (e.g. `GIT_REPO_DIR`) never reach Jenkins | `triggerHelixOnpremPipelineBuild()` deletes `AGENT`, `HELM_NODE`, `GIT_REPO_DIR`, `GIT_USER_HOME_DIR` when `isJenkinsInCluster` |

### Jenkins API behaviour (confirmed)

- **Key omitted from POST** → not in Groovy binding → `MissingPropertyException`
- **Key present with `""`** → binds blank (not “use default”)
- **UI Build with Parameters** → all job params collected (defaults included); API JSON builds do not

### `get last` vs `get defaults`

- `get last` reads **that build’s** `ParametersAction` — params never bound to an API-triggered run are absent from source data
- Keeping empties on `get` helps round-trip for params that **were** present but blank; it does **not** recreate params missing from the build record

---

## Observed failure example

`-k build build.json` on containerized Jenkins 26.1.01:

- JSON included `"GIT_REPO_DIR": "http://gitea:3000/ciadmin"`
- HITT stripped it before POST (`isJenkinsInCluster`)
- Pipeline failed at `WorkflowScript:220` with `MissingPropertyException: GIT_REPO_DIR`
- Conflicts with HITT validation elsewhere that **requires** `GIT_REPO_DIR` for containerized DE

---

## Proposed direction (layered)

### Layer 1 — Bugfixes (narrow, do first)

- [ ] **Stop stripping `GIT_REPO_DIR` and `GIT_USER_HOME_DIR` on in-cluster build**  
  Keep stripping `AGENT` and `HELM_NODE` only (fixed agent on containerized DE).  
  Location: `triggerHelixOnpremPipelineBuild()` — `del(.AGENT, .HELM_NODE, …)`

- [ ] **Update `README-pipeline-mode.md`**  
  Document that API builds do not apply Jenkins defaults; list what HITT still strips (file params, pipeline checkboxes default false, in-cluster agent fields).

### Layer 2 — Main fix: merge defaults at build time

- [ ] **Merge job defaults under user JSON before POST**  
  `final = getPipelineDefaults()` then overlay keys from input file (input wins).  
  Location: `triggerHelixOnpremPipelineBuild()` before the Jenkins `{parameter: [...]}` wrapper.

- [ ] **Apply same merge for `kickstart`** (if not already equivalent via manifest + defaults).

- [ ] **Reject or warn on `***REDACTED***` password placeholders** in build JSON (fail fast with pointer to `-p` on `get`).

Implications:

- Guarantees every job-defined string/boolean param is sent even from partial JSON
- Default passwords from Jenkins may still be empty — `-p` on export still required for secrets
- Does not affect FILE parameters (see below)

### Layer 3 — Export modes on `get` (optional, complementary)

Choose one or combine:

- [ ] **Option A:** Stop dropping empty values on `get` (noisier JSON; still strip `SEPARATOR_*`)
- [ ] **Option B:** Add `-k "get complete …"` (or flag) — full param set from defaults ∪ source; keep current `get` for human-readable export
- [ ] **Option C:** Add `-k "get buildable lastsuccessful"` — opinionated path: merge defaults + last good run

Recommendation from discussion: **Layer 2 is essential**; Layer 3 Option B avoids polluting the default `get` output.

### Layer 4 — Validation and UX

- [ ] **Pre-POST validation:** compare merged payload to job param list; warn on missing required secrets
- [ ] **Clearer errors** when Groovy binding would fail (before queueing build)
- [ ] **Log merged param count** vs override count (already partially done)

### Layer 5 — Out of scope / unchanged

- [ ] **FILE parameters** — continue stripping on build; cannot upload via JSON POST. User must **Rebuild** in Jenkins for certs/config files. Document in TODO closure / README.
- [ ] **Pipeline section checkboxes** — continue defaulting missing flags to `"false"` (safety: no accidental full deploy)
- [ ] **Fully unattended deploy** — blocked by file uploads and intentional checkbox defaults unless explicitly set in JSON

---

## FILE parameters (explicit non-goals)

The three get/build proposals **do not** change FILE handling:

| Step | Behaviour |
|------|-----------|
| `get` | File param names may appear as `""` or old filename; no file bytes in JSON |
| `build` | `getPipelineFileParams()` always `del()` file keys before POST |
| Merge defaults | Would add empty file keys then strip again — no net change |

Future enhancement (separate effort): multipart upload or document-only `_fileParameters` manifest in export.

---

## Current code references

| Area | File | Notes |
|------|------|-------|
| Empty strip on `get` | `hitt.sh` — `getJenkinsPipelineValues()` jq `walk` | `elif ($e.value == "") then empty` |
| In-cluster del on `build` | `hitt.sh` — `triggerHelixOnpremPipelineBuild()` | Still deletes `GIT_REPO_DIR`, `GIT_USER_HOME_DIR` |
| Defaults filter only | `hitt.sh` — `with_entries(select(...))` | Filters input to known keys; does **not** add missing defaults |
| File param strip | `hitt.sh` — `reduce $file_params[]` | Independent of above |
| Kickstart export | `hittPipelineJsonForKickstartExport()` | Strips file params + `INPUT_CONFIG_METHOD`; forces pipeline flags false |

---

## Decision matrix (from discussion)

| Approach | Fixes missing params | Fixes empty round-trip | Minimal JSON | Unattended build* |
|----------|---------------------|------------------------|--------------|-------------------|
| Stop dropping empty on `get` | Partial | Yes | No | Partial |
| Don't drop in-cluster GIT_* on `build` | Partial | N/A | Yes | Partial |
| **Merge defaults at `build`** | **Yes** | N/A | Yes | **Yes*** |
| `get complete` + `build` | Yes | Yes | No | Yes* |
| Keep rebuild-only workflow | No | No | Yes | No |

\*Excludes file params; pipeline flags must be set explicitly in JSON.

---

## Suggested implementation order

1. Fix in-cluster `del()` list (`GIT_REPO_DIR`, `GIT_USER_HOME_DIR` pass through)
2. Implement merge-at-build (defaults base + JSON overrides)
3. Add build validation for redacted passwords
4. Add optional `get complete` export mode
5. Update docs and use-cases (`README-pipeline-mode.md`, `docs/hitt/use-cases.json`)

---

## Related but separate

- **`ensureKubectlBin`** — early `hitt.conf` source before kubectl checks (implemented separately; not part of get/build)
- **Skip kubectl for Jenkins-only modes** (`-k get|build|delete`, `-o`) — optional follow-up so pipeline export/build does not require local cluster access

---

## Test plan (when implementing)

- [ ] `-k "get defaults"` / `get lastsuccessful` — with and without empty-param retention mode
- [ ] `-k "build file.json"` on containerized DE — verify `GIT_REPO_DIR`, `GIT_USER_HOME_DIR` in queued build parameters
- [ ] Partial JSON (omit 10+ params) — build succeeds without `MissingPropertyException`
- [ ] JSON with `***REDACTED***` passwords — warn or fail clearly
- [ ] `get last` after API build — documents which params are absent from build record
- [ ] FILE params — confirm still excluded from POST; Rebuild workflow documented
