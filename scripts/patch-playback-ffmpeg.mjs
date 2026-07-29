#!/usr/bin/env node
/**
 * playback-cli expects Homebrew ffmpeg-full at $HOMEBREW_PREFIX/opt/ffmpeg-full/bin.
 * On Linux/WSL, use system ffmpeg via PLAYBACK_FFMPEG_BIN or PATH fallback.
 * Idempotent — safe to run on every npm install.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const MARKER = '/* helix-tools: ffmpeg resolver */';
const cliPath = join(process.cwd(), 'node_modules', 'playback-cli', 'dist', 'cli.js');

if (!existsSync(cliPath)) {
  process.exit(0);
}

let src = readFileSync(cliPath, 'utf8');
if (src.includes(MARKER)) {
  console.log('playback-cli: ffmpeg patch already applied');
  process.exit(0);
}

const needle = 'var FFMPEG_FULL_BIN = `${HOMEBREW_PREFIX}/opt/ffmpeg-full/bin`;';
if (!src.includes(needle)) {
  console.error('playback-cli: ffmpeg patch failed — unexpected cli.js layout');
  process.exit(1);
}

const replacement = `${MARKER}
var FFMPEG_FULL_BIN = (() => {
  const fromEnv = process.env["PLAYBACK_FFMPEG_BIN"];
  if (fromEnv) return fromEnv.replace(/\\/$/, "");
  const brewBin = \`\${HOMEBREW_PREFIX}/opt/ffmpeg-full/bin\`;
  if (existsSync(\`\${brewBin}/ffmpeg\`) && existsSync(\`\${brewBin}/ffprobe\`)) return brewBin;
  return "";
})();
function helixFfmpegTool(name) {
  return FFMPEG_FULL_BIN ? \`\${FFMPEG_FULL_BIN}/\${name}\` : name;
}`;

src = src.replace(needle, replacement);
src = src.replaceAll('`${FFMPEG_FULL_BIN}/ffprobe`', 'helixFfmpegTool("ffprobe")');
src = src.replaceAll('`${FFMPEG_FULL_BIN}/ffmpeg`', 'helixFfmpegTool("ffmpeg")');
src = src.replace(
  'PATH: `${FFMPEG_FULL_BIN}:${process.env.PATH ?? ""}`',
  'PATH: FFMPEG_FULL_BIN ? `${FFMPEG_FULL_BIN}:${process.env.PATH ?? ""}` : (process.env.PATH ?? "")',
);

writeFileSync(cliPath, src);
console.log('playback-cli: applied ffmpeg PATH patch');
