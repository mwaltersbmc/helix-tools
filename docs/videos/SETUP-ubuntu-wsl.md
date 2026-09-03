# HITT video pipeline — Ubuntu 24.04 on WSL2

Recommended environment for rendering narrated terminal videos (VHS + Azure Speech + ffmpeg).

Clone the repo **inside the WSL filesystem** (e.g. `~/dev/github/helix-tools`), not under `/mnt/c`, for Docker bind mounts and file performance.

## 1. Install system dependencies

```bash
bash scripts/install-ubuntu-wsl-deps.sh --install
```

This installs: `curl`, `jq`, `ffmpeg`, `git`, Node.js 22, VHS (Charm apt), Google Chrome (for native VHS), `ttyd` (user-local), and checks Docker.

## 2. Clone and prepare the repo

```bash
cd ~/dev/github/helix-tools
chmod +x scripts/video/run-vhs.sh docs/videos/demo/hitt.sh
npm install
```

## 3. Azure Speech credentials

Create an [Azure Speech resource](https://portal.azure.com/#create/Microsoft.CognitiveServicesSpeechServices), then:

```bash
cp .env.example .env
nano .env   # AZURE_SPEECH_KEY and AZURE_SPEECH_REGION
```

## 4. Validate and render

```bash
npm run video:validate -- info-cluster-status
npm run video:render -- info-cluster-status
```

Output appears under `docs/assets/videos/info-cluster-status/`.

## Docker (default for VHS)

Ensure Docker Desktop is running with WSL integration, or Docker Engine inside WSL:

```bash
docker info
```

To use native VHS instead (requires `vhs`, `ttyd`, Chrome on the host):

```bash
node scripts/video/render.mjs --native info-cluster-status
```

## Partial renders

```bash
npm run video:tts -- info-cluster-status   # Azure narration only
npm run video:vhs -- info-cluster-status   # terminal recording only (uses existing segments.json if present)
```

## PATH

If `node` or `npm` are missing after install, ensure NodeSource Node 22 is on PATH. For native VHS, add ttyd:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## See also

- [docs/videos/README.md](README.md) — full pipeline reference
