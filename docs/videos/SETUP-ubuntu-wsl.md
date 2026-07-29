# Video pipeline setup — Ubuntu 24.04 LTS on WSL2

Use this guide when the repo lives in **WSL2** (e.g. `~/dev/github/helix-tools`). Prefer the Linux filesystem (`~/...`), not `/mnt/c/...`, for `npm`, `vhs`, and git performance.

All commands below are run **inside WSL** (Ubuntu 24.04), from a bash shell.

---

## 1. Base packages

```bash
sudo apt update
sudo apt install -y \
  curl ca-certificates gnupg jq \
  ffmpeg \
  git bash
```

- **ffmpeg** — playback mux + our ffmpeg patch uses `/usr/bin/ffmpeg` and `/usr/bin/ffprobe`.

**Do not** run `apt install chromium-browser` on Ubuntu 24.04 — that package is a transitional wrapper that installs **Snap** Chromium. This guide uses only `.deb` packages and user-local binaries (no Snap, no Flatpak).

Optional: `python3-pip` if you use custom entries in `voices.yaml` with the download script (`pip install pyyaml`).

---

## 2. Docker (default VHS runner — silent + narrated)

Install [Docker Desktop](https://docs.docker.com/desktop/) on Windows and enable **WSL integration**, or install Docker Engine inside WSL.

Verify inside WSL:

```bash
docker info
docker pull ghcr.io/charmbracelet/vhs
```

Both `./scripts/render-videos.sh` and `npm run playback:render` use this image by default. No host `vhs`, `ttyd`, or browser install needed unless you pass `--native`.

---

## 3. Google Chrome (`--native` VHS only — `.deb`, not Snap)

**Skip** if you use Docker (default) for all renders.

**Required only for** `--native`: `./scripts/render-videos.sh --native` or `./scripts/render-playback.sh --native`.

```bash
curl -fsSL -o /tmp/google-chrome.deb \
  https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install -y /tmp/google-chrome.deb
rm -f /tmp/google-chrome.deb
google-chrome-stable --version
```

If you previously installed the Snap wrapper, remove it first:

```bash
sudo snap remove chromium 2>/dev/null || true
sudo apt remove -y chromium-browser 2>/dev/null || true
```

For ongoing updates via `apt` (optional), add [Google’s Chrome repository](https://www.google.com/chrome/) instead of the one-off `.deb` above.

---

## 4. Node.js 22+ (required by playback-cli)

Ubuntu 24.04 may ship an older Node in `apt`. Use **NodeSource 22.x**:

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
node --version   # expect v22.x
npm --version
```

Alternative: [fnm](https://github.com/Schniz/fnm) or [nvm](https://github.com/nvm-sh/nvm) if you prefer user-local Node.

---

## 5. VHS (`--native` only — Charm apt repository)

Skip if you use Docker (step 2).

```bash
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
sudo apt update
sudo apt install -y vhs
vhs --version
```

---

## 6. ttyd (`--native` only — not in Charm apt)

Skip if you use Docker (step 2).

Install to `~/.local/bin` (no sudo):

```bash
mkdir -p ~/.local/bin
curl -fsSL -o ~/.local/bin/ttyd \
  https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64
chmod +x ~/.local/bin/ttyd
```

Ensure `~/.local/bin` is on PATH (add to `~/.bashrc` if needed):

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
ttyd --version
```

---

## 7. Piper TTS (playback narration)

Install **uv**, then **piper-tts**:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source "$HOME/.local/bin/env"   # or open a new shell

uv tool install piper-tts
piper --help
```

Our render scripts prepend `~/.local/bin` to PATH automatically.

---

## 8. Helix-tools project setup

```bash
cd ~/dev/github/helix-tools   # your clone path

chmod +x scripts/*.sh docs/videos/demo/hitt.sh

npm install
npm run playback:setup
```

`playback:setup` installs `playback-cli`, applies the **ffmpeg PATH patch**, checks tools, and downloads the default Piper voice.

Download extra voices:

```bash
./scripts/download-playback-voice.sh --list
./scripts/download-playback-voice.sh alan
```

---

## 9. Render a narrated video

Uses Docker for the terminal capture step by default:

```bash
npm run playback:validate -- info-cluster-status
npm run playback:render -- info-cluster-status
```

Output: `docs/assets/videos/playback/info-cluster-status/info-cluster-status.mp4` (and `.gif`, `.vtt`, `.srt`).

---

## 10. Silent VHS only (optional)

`render-videos.sh` uses **Docker by default** (browser and VHS deps are inside the image — no Chrome install needed):

```bash
./scripts/render-videos.sh info-cluster-status
```

Requires Docker Desktop with WSL integration, or Docker Engine in WSL. For host-native VHS instead:

```bash
./scripts/render-videos.sh --native info-cluster-status
```

Native mode needs the Chrome install (step 2), `vhs`, and `ttyd` from earlier steps.

---

## Troubleshooting (WSL2)

| Symptom | Fix |
|---------|-----|
| `piper is not installed` | `uv tool install piper-tts`; ensure `~/.local/bin` on PATH |
| `ffprobe ENOENT` under `/usr/local/opt/ffmpeg-full` | Run `npm install` (applies patch); or `export PLAYBACK_FFMPEG_BIN` via render script |
| `execvp failed` in video | Set `vhs.shell: bash` in `meta.yaml` (pilot tapes already do) |
| VHS hangs / blank frames (`--native`) | Install `google-chrome-stable` (step 3); run from `~/` not `/mnt/c` |
| Docker errors | Start Docker; `docker pull ghcr.io/charmbracelet/vhs` |
| `Node.js >= 22` errors | Install Node 22 via NodeSource (step 4) |
| Slow renders | Normal on first run; headless Chrome + VHS capture is heavy |

Optional timing editor (requires Go):

```bash
sudo apt install -y golang-go   # or use upstream Go tarball
go install github.com/philsherry/playback/tui/cmd/playback-tui@latest
~/go/bin/playback-tui docs/videos/playback/info-cluster-status
```

---

## Regenerating use-case bundled JS (Windows or WSL)

From repo root on **Windows** (PowerShell):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File docs\hitt\update-bundled-data.ps1
```

On **WSL** (if PowerShell is not available):

```bash
node -e "
const fs=require('fs');
const p='docs/hitt/use-cases.json';
const j=fs.readFileSync(p,'utf8').trim();
fs.writeFileSync('docs/hitt/use-cases-data.js',
  '/* Generated from use-cases.json */\\nwindow.HITT_USE_CASES = '+j+';\\n');
"
```

See also: [README.md](README.md).
