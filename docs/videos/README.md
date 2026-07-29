# HITT terminal videos (VHS + Playback)

On-demand terminal recordings for selected [HITT use cases](../hitt/use-cases.json).

| Pipeline | Tooling | Output |
|----------|---------|--------|
| **Silent** | [VHS](https://github.com/charmbracelet/vhs) `.tape` files | MP4 + GIF |
| **Narrated** | [playback-cli](https://github.com/philsherry/playback) YAML tapes | MP4 + GIF + VTT/SRT captions + voiceover |

Videos are **not** rendered on commit — run a render script locally when you want new assets.

## Directory layout

| Path | Purpose |
|------|---------|
| `docs/videos/*.tape` | Silent VHS tapes (legacy / quick renders) |
| `docs/videos/playback/<id>/` | **Playback** source — `tape.yaml` + `meta.yaml` per use case |
| `docs/videos/playback/_template/` | Copy this when adding a new narrated use case |
| `docs/videos/playback/voices/` | Piper ONNX models (downloaded by setup script) |
| `docs/videos/demo/` | Offline demo helpers (`hitt.sh` mock, sample `hitt.conf`, fixtures) |
| `docs/assets/videos/` | Silent VHS output (MP4/GIF) |
| `docs/assets/videos/playback/<id>/` | Playback output (MP4, GIF, captions, segments) |
| `docs/hitt/use-cases.json` | Canonical manifest — `video` + `video.playback` per use case |
| `scripts/render-videos.sh` | Silent VHS render |
| `scripts/render-playback.sh` | Narrated playback render |
| `scripts/setup-playback.sh` | One-time playback dependency + voice setup |
| `scripts/download-playback-voice.sh` | Download Piper voice models by name |
| `scripts/vhs-docker-lib.sh` | Shared Docker VHS helpers |
| `scripts/vhs-docker-shim.sh` | PATH shim so playback-cli runs VHS in Docker |
| `scripts/install-ubuntu-wsl-deps.sh` | Ubuntu 24.04 / WSL2 dependency install helper |
| `docs/videos/SETUP-ubuntu-wsl.md` | Full WSL2 setup guide |
| `playback.config.mjs` | Playback output paths and default voice |
| `voices.yaml` | Piper voice catalogue and synthesis tuning (repo root) |

## Manifest (`use-cases.json`)

Every use case has:

```json
"video": {
  "enabled": false,
  "tape": "<use-case-id>.tape",
  "playback": {
    "dir": "<use-case-id>",
    "enabled": false
  }
}
```

| Field | Meaning |
|-------|---------|
| `video.enabled` | Include in `./scripts/render-videos.sh` when no IDs passed |
| `video.playback.enabled` | Include in `./scripts/render-playback.sh` when no IDs passed |
| `video.playback.dir` | Directory under `docs/videos/playback/` (usually same as use case `id`) |

**Pilot use cases** (both silent + playback enabled): `download-hitt`, `info-cluster-status`, `hitt-config-change`.

After JSON changes, regenerate bundled help data:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File docs\hitt\update-bundled-data.ps1
```

---

## Narrated videos (Playback) — recommended

One command rebuilds terminal video, **piper-tts voiceover**, and **captions**, with timing synced automatically.

### Setup (once per machine)

**Ubuntu 24.04 on WSL2:** see **[SETUP-ubuntu-wsl.md](SETUP-ubuntu-wsl.md)** (recommended). Quick path:

```bash
# Inside WSL — clone under ~/ not /mnt/c
bash scripts/install-ubuntu-wsl-deps.sh --install
cd ~/dev/github/helix-tools
chmod +x scripts/*.sh docs/videos/demo/hitt.sh
npm install
npm run playback:setup
```

Or install dependencies manually (same guide), then from repo root:

```bash
chmod +x scripts/setup-playback.sh scripts/render-playback.sh scripts/download-playback-voice.sh
npm run playback:setup
```

Installs `playback-cli`, checks **Docker** (default VHS), `ffmpeg`, and `piper`, applies the ffmpeg patch, and downloads the default Piper voice.

### Download another voice

```bash
chmod +x scripts/download-playback-voice.sh   # once

./scripts/download-playback-voice.sh --list
./scripts/download-playback-voice.sh alan
npm run playback:voice -- alan alba
```

Then set `voices: [alan]` in the tape’s `meta.yaml` and re-render.

Built-in names: `alan`, `alba`, `northern_english_male`, `southern_english_female`, `aru_09`. Catalogue and Piper tuning live in [`voices.yaml`](../../voices.yaml) at the repo root; download with `scripts/download-playback-voice.sh`.

`piper` from `uv tool install piper-tts` is usually in `~/.local/bin`. The render scripts add that to `PATH` automatically.

**Linux/WSL:** `playback-cli` defaults to Homebrew `ffmpeg-full`; this repo patches it on `npm install` to use system `ffmpeg`/`ffprobe` from `/usr/bin` (or `PLAYBACK_FFMPEG_BIN`). Re-run `npm install` if you see `ffprobe ENOENT` under `/usr/local/opt/ffmpeg-full`.

### Render

VHS terminal capture uses **Docker by default** (via a PATH shim). TTS and mux still run on the host (`piper`, `ffmpeg`).

```bash
# Validate YAML without recording
npm run playback:validate -- info-cluster-status

# Full pipeline (Docker VHS + TTS + captions + mux)
npm run playback:render -- info-cluster-status
npm run playback:render -- download-hitt hitt-config-change

# All use cases with video.playback.enabled == true
npm run playback:render

# Terminal only (no narration) — useful while editing commands
npm run playback:vhs-only -- info-cluster-status

# Native VHS on the host instead of Docker
npm run playback:render -- --native info-cluster-status
```

Output: `docs/assets/videos/playback/<id>/<id>.mp4`, `.gif`, `.vtt`, `.srt`.

### Timing tweaks

If narration overlaps or feels rushed:

```bash
# Audit pause values against synthesized audio
./scripts/render-playback.sh --audit info-cluster-status

# Auto-fix shortfalls in tape.yaml
./scripts/render-playback.sh --audit-fix info-cluster-status
```

Optional visual editor (install separately):

```bash
go install github.com/philsherry/playback/tui/cmd/playback-tui@latest
playback-tui docs/videos/playback/info-cluster-status
```

### Add a narrated use case

1. Copy `docs/videos/playback/_template/` → `docs/videos/playback/<id>/`.
2. Edit `tape.yaml` (commands + `narration` fields) and `meta.yaml` (title, tags, `vhsCwd: "."`).
3. Set `"playback": { "dir": "<id>", "enabled": true }` in `use-cases.json`.
4. Regenerate `use-cases-data.js`.
5. `npm run playback:render -- <id>`.

Use `docs/videos/demo/` mocks when a live cluster is not available. Set `vhsCwd: "."` in `meta.yaml` so paths like `docs/videos/demo` resolve from the repo root.

**Playback YAML rule:** `command` / `commands` strings must not contain double quotes — use single quotes for shell arguments (e.g. `bash hitt.sh -m 'info cluster'`).

**Caption length:** keep each `narration` field to **~25 words or fewer** (playback warns above that limit — long text is hard to read as burned-in captions).

**Shell:** playback defaults to **zsh**; set `vhs.shell: bash` in `meta.yaml` on WSL/Linux or you get `execvp failed` in the recording.

---

## Silent videos (VHS only)

For quick terminal captures without narration, use the VHS `.tape` files under `docs/videos/`.

### Prerequisites

**Docker** is the default for VHS in both silent and narrated pipelines. Install [Docker Desktop](https://docs.docker.com/desktop/) with WSL integration, or Docker Engine inside WSL.

Host tools still required for narrated videos: **Node 22+**, **ffmpeg**, **piper**, and Piper voice models.

For **`--native`** (host VHS without Docker), see [SETUP-ubuntu-wsl.md](SETUP-ubuntu-wsl.md) — requires `vhs`, `ttyd`, and a Chromium-based browser.

### Local rendering

```bash
chmod +x scripts/render-videos.sh docs/videos/demo/hitt.sh   # once

# Default — VHS in Docker (WSL, Linux, Windows)
./scripts/render-videos.sh                           # all enabled use cases
./scripts/render-videos.sh info-cluster-status       # one use case

# Native VHS on the host (requires vhs + ttyd + browser)
./scripts/render-videos.sh --native info-cluster-status
```

The script resolves tape files from the manifest, runs VHS, and prints paths under `docs/assets/videos/`.

## Troubleshooting (silent VHS)

### Docker not available

Start Docker Desktop (enable WSL integration) or install Docker Engine in WSL, then re-run. Or use native VHS:

```bash
./scripts/render-videos.sh --native info-cluster-status
```

### Hangs after `Set TypingSpeed` / Ctrl+C does nothing (`--native` on Windows)

This is a **known native Windows issue**: VHS depends on `ttyd`, which often fails to spawn the terminal on Windows 11 / Git Bash. The process appears stuck and may ignore Ctrl+C; a stale `ttyd.exe` can block later runs.

**Fix:** omit `--native` so Docker is used (default), or run from **WSL** with Docker.

**If you must use native on Windows:**

- Kill stale processes: `taskkill //F //IM ttyd.exe` (and close any Edge/Chrome tab opened by ttyd)
- Try [ttyd 1.7.3](https://github.com/tsl0922/ttyd/releases/tag/1.7.3) or an MSVC build — see [vhs#437](https://github.com/charmbracelet/vhs/issues/437), [vhs#631](https://github.com/charmbracelet/vhs/issues/631)

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
