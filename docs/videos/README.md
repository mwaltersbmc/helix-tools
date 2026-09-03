# HITT terminal videos (VHS + Azure Speech)

On-demand terminal recordings for selected [HITT use cases](../hitt/use-cases.json).

| Stage | Tooling | Output |
|-------|---------|--------|
| **Terminal** | [VHS](https://github.com/charmbracelet/vhs) (Docker by default) | `terminal.mp4` |
| **Narration** | [Azure Speech](https://learn.microsoft.com/en-us/azure/ai-services/speech-service/) | `segments/*.wav` |
| **Final** | ffmpeg mux + captions | MP4, GIF, VTT, SRT |

Videos are **not** rendered on commit — run a render script locally when you want new assets.

## Directory layout

| Path | Purpose |
|------|---------|
| `docs/videos/scripts/<id>/script.yaml` | Director script — steps, commands, narration |
| `docs/videos/scripts/_template/` | Copy when adding a new use case video |
| `docs/videos/demo/` | Offline demo helpers (`hitt.sh` mock, sample `hitt.conf`, fixtures) |
| `docs/assets/videos/<id>/` | Render output (MP4, GIF, captions, segments) |
| `azure/voices.yaml` | Azure Speech voice catalogue |
| `scripts/video/render.mjs` | Full pipeline orchestrator |
| `scripts/video/run-vhs.sh` | VHS runner (Docker or native) |
| `scripts/vhs-docker-lib.sh` | Shared Docker VHS helpers |
| `docs/hitt/use-cases.json` | Canonical manifest — `video` per use case |

## Manifest (`use-cases.json`)

Every use case may have:

```json
"video": {
  "enabled": false,
  "script": "info-cluster-status",
  "voice": "azure_ryan_chat"
}
```

| Field | Meaning |
|-------|---------|
| `video.enabled` | Include in `npm run video:render` when no IDs passed |
| `video.script` | Directory under `docs/videos/scripts/` (defaults to use case `id`) |
| `video.voice` | Key from `azure/voices.yaml` (overrides script default) |

**Pilot use cases** (`video.enabled: true`): `download-hitt`, `info-cluster-status`, `hitt-config-change`.

After JSON changes, regenerate bundled help data:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File docs\hitt\update-bundled-data.ps1
```

---

## Setup (once per machine)

**Ubuntu 24.04 on WSL2:** see **[SETUP-ubuntu-wsl.md](SETUP-ubuntu-wsl.md)**.

### Azure Speech credentials

Create a Speech resource in Azure Portal, then configure credentials (never commit keys):

```bash
cp .env.example .env
# Edit .env — set AZURE_SPEECH_KEY and AZURE_SPEECH_REGION
```

Or export directly:

```bash
export AZURE_SPEECH_KEY="..."
export AZURE_SPEECH_REGION="uksouth"
```

### Dependencies

```bash
# Inside WSL — clone under ~/ not /mnt/c
bash scripts/install-ubuntu-wsl-deps.sh --install
cd ~/dev/github/helix-tools
chmod +x scripts/video/run-vhs.sh docs/videos/demo/hitt.sh
npm install
```

Requires: **Node 22+**, **Docker** (default VHS), **ffmpeg**, and Azure Speech credentials for narrated renders.

---

## Render

VHS terminal capture uses **Docker by default**. Azure TTS and ffmpeg run on the host.

```bash
# Validate YAML without recording
npm run video:validate -- info-cluster-status

# Full pipeline (Azure TTS + Docker VHS + captions + mux)
npm run video:render -- info-cluster-status
npm run video:render -- download-hitt hitt-config-change

# All use cases with video.enabled == true
npm run video:render

# Partial stages
npm run video:tts -- info-cluster-status    # narration WAV only
npm run video:vhs -- info-cluster-status    # terminal recording only

# Native VHS on the host instead of Docker
node scripts/video/render.mjs --native info-cluster-status
```

Output: `docs/assets/videos/<id>/<id>.mp4`, `.gif`, `.vtt`, `.srt`.

### Voices

Edit `azure/voices.yaml` or set `voice:` in `script.yaml` / `use-cases.json`. Built-in keys:

| Key | Azure voice |
|-----|-------------|
| `azure_ryan_chat` | `en-GB-RyanNeural` (chat style) — default |
| `azure_ryan` | `en-GB-RyanNeural` |
| `azure_sonia` | `en-GB-SoniaNeural` (cheerful) |
| `azure_libby` | `en-GB-LibbyNeural` |

---

## Add a narrated use case

1. Copy `docs/videos/scripts/_template/` → `docs/videos/scripts/<id>/`.
2. Edit `script.yaml` (commands + `narration` fields).
3. Set `"video": { "enabled": true, "script": "<id>", "voice": "azure_ryan_chat" }` in `use-cases.json`.
4. Regenerate `use-cases-data.js`.
5. `npm run video:render -- <id>`.

Use `docs/videos/demo/` mocks when a live cluster is not available.

**Script rules:**

- `command` / `commands` strings must not contain double quotes — use single quotes for shell arguments (e.g. `bash hitt.sh -m 'info cluster'`).
- Multi-word HITT option values need single quotes inside the command string.
- Keep each `narration` field to **~25 words or fewer** (validator warns above that limit).

**Step types:**

| Fields | Effect |
|--------|--------|
| `hide` + `commands` + `show` | Hidden setup, then reveal terminal |
| `comment` | Visible `#` title line |
| `narration` | Azure voiceover (timing drives VHS pauses) |
| `command` | Typed and executed after narration |
| `pauseAfter` | Extra ms after command output (or after narration-only step) |

---

## Troubleshooting

### Docker not available

Start Docker Desktop (enable WSL integration) or install Docker Engine in WSL. Or use native VHS:

```bash
node scripts/video/render.mjs --native info-cluster-status
```

### ffmpeg / WAV errors on WSL

If ffmpeg fails with `Invalid data found when processing input` and the path shows `C:\Users\...`, Windows ffmpeg is being picked up via WSL interop. Install Linux ffmpeg:

```bash
sudo apt install -y ffmpeg
which ffmpeg   # should be /usr/bin/ffmpeg
```

The pipeline prefers `/usr/bin/ffmpeg` automatically on WSL. Override with `FFMPEG_BIN` / `FFPROBE_BIN` if needed.

After fixing ffmpeg, delete stale segments and re-render so WAV files are rewritten:

```bash
rm -rf docs/assets/videos/info-cluster-status/segments
npm run video:render -- info-cluster-status
```


Check `AZURE_SPEECH_KEY` and `AZURE_SPEECH_REGION` match your Speech resource. Run `npm run video:tts -- info-cluster-status` to isolate TTS.

### Hangs after `Set TypingSpeed` (native VHS on Windows)

Known native Windows issue with `ttyd`. **Fix:** use Docker (default) or run from **WSL**.

---

## Committing generated assets

When output looks correct:

```bash
git add docs/assets/videos/
git commit -m "docs(videos): add <use-case-id> terminal recordings"
```

## Deferred

- GitHub Actions workflow for CI rendering
- Embedding videos in the HITT help site (`docs/hitt/index.html`, `app.js`)
