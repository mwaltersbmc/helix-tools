# HITT terminal videos (VHS)

On-demand terminal recordings for selected [HITT use cases](../hitt/use-cases.json), generated with [VHS](https://github.com/charmbracelet/vhs) (MIT license). Videos are **not** rendered on commit — run the render script locally when you want new assets.

## Directory layout

| Path | Purpose |
|------|---------|
| `docs/videos/*.tape` | VHS source tapes (one per use case, named `<use-case-id>.tape`) |
| `docs/videos/demo/` | Offline demo helpers (`hitt.sh` mock, sample `hitt.conf`, fixtures) |
| `docs/assets/videos/` | Rendered `.mp4` and `.gif` output (commit manually when satisfied) |
| `docs/hitt/use-cases.json` | Canonical manifest — each use case has a `video` object |
| `scripts/render-videos.sh` | Local selective render script |

## Enable or disable a use case

Edit [`docs/hitt/use-cases.json`](../hitt/use-cases.json). Every use case has:

```json
"video": {
  "enabled": false,
  "tape": "<use-case-id>.tape"
}
```

Set `"enabled": true` for use cases that should render when you run the script with **no** arguments. Explicit IDs on the command line always render, regardless of `enabled`.

After JSON changes, regenerate the bundled help data:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File docs\hitt\update-bundled-data.ps1
```

Commit `use-cases.json` and `use-cases-data.js` together.

**Initial pilot use cases** (enabled by default): `download-hitt`, `info-cluster-status`, `hitt-config-change`.

## Prerequisites

**Linux / Deployment Engine / WSL** — native VHS:

- **VHS** — `brew install vhs` or `go install github.com/charmbracelet/vhs@latest`
- **ffmpeg** and **ttyd** — required by VHS (usually on PATH when VHS is installed)
- **bash**, **jq** (optional; falls back to `python3`)

**Windows / Git Bash** — use Docker (native VHS often hangs; see Troubleshooting):

- **Docker Desktop** running
- Render with `--docker` (auto-selected on Windows/Git Bash)

Run from the **repository root**.

## Local rendering

```bash
chmod +x scripts/render-videos.sh docs/videos/demo/hitt.sh   # once

# Linux / WSL / Deployment Engine
./scripts/render-videos.sh                           # all enabled use cases
./scripts/render-videos.sh info-cluster-status       # one use case

# Windows / Git Bash (recommended)
./scripts/render-videos.sh --docker info-cluster-status
./scripts/render-videos.sh --docker download-hitt hitt-config-change
```

The script resolves tape files from the manifest, runs VHS, and prints paths under `docs/assets/videos/`.

## Troubleshooting

### Hangs after `Set TypingSpeed` / Ctrl+C does nothing

This is a **known native Windows issue**: VHS depends on `ttyd`, which often fails to spawn the terminal on Windows 11 / Git Bash. The process appears stuck and may ignore Ctrl+C; a stale `ttyd.exe` can block later runs.

**Fix (recommended):** use Docker:

```bash
./scripts/render-videos.sh --docker info-cluster-status
```

**Alternatives:**

- Run from **WSL** with native `vhs` installed
- Kill stale processes: `taskkill //F //IM ttyd.exe` (and close any Edge/Chrome tab opened by ttyd)
- Native Windows: try [ttyd 1.7.3](https://github.com/tsl0922/ttyd/releases/tag/1.7.3) or an MSVC build — see [vhs#437](https://github.com/charmbracelet/vhs/issues/437), [vhs#631](https://github.com/charmbracelet/vhs/issues/631)

Force native (not recommended on Windows): `VHS_FORCE_NATIVE=1 ./scripts/render-videos.sh info-cluster-status`

## Committing generated assets

When output looks correct:

```bash
git add docs/assets/videos/
git commit -m "docs(videos): add <use-case-id> terminal recordings"
```

Binary files are stored in the repo (not Git LFS) for this phase.

## Adding a new tape

1. Set `"enabled": true` (optional) and ensure `"tape": "<id>.tape"` in the manifest.
2. Create `docs/videos/<id>.tape` with:
   - `Output docs/assets/videos/<id>.mp4` and `.gif`
   - `Source "docs/videos/_settings.tape"` for shared terminal styling (or copy those `Set` lines)
   - Hidden setup (`Hide` / `Show`) for `cd`, mock env — avoid `clear` and `vi` (can hang in VHS)
   - Commands aligned with the use case’s `commands[]` in the manifest
3. Use **double quotes** for multi-word HITT option values (e.g. `-m "info cluster"`).
4. Use `docs/videos/demo/` mocks when a live cluster or Jenkins is not available.
5. Regenerate `use-cases-data.js` if you changed the manifest.

## Deferred

- GitHub Actions workflow for CI rendering and auto-commit
- Embedding videos in the HITT help site (`docs/hitt/index.html`, `app.js`)
