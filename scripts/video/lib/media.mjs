import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fromRepoRelative, isWsl } from './paths.mjs';

function resolveBin(envName, linuxDefault, fallback) {
  if (process.env[envName]) return process.env[envName];
  if (isWsl() && fs.existsSync(linuxDefault)) return linuxDefault;
  return fallback;
}

export function ffmpegBin() {
  return resolveBin('FFMPEG_BIN', '/usr/bin/ffmpeg', 'ffmpeg');
}

export function ffprobeBin() {
  return resolveBin('FFPROBE_BIN', '/usr/bin/ffprobe', 'ffprobe');
}

/** Standard rate for MP4/AAC — avoids players treating 24 kHz Azure audio as ~2× speed. */
export const OUTPUT_SAMPLE_RATE = 48000;

/** Run ffmpeg/ffprobe with inherited stdio (avoids pipe deadlock on verbose tools). */
export function runMedia(cmd, args, label) {
  if (label) {
    console.log(`  ${label}`);
  }
  const result = spawnSync(cmd, args, { stdio: 'inherit' });
  if (result.status !== 0) {
    throw new Error(`${cmd} failed with exit code ${result.status ?? 'unknown'}`);
  }
}

/** Run ffprobe and capture stdout (small output). */
export function runMediaCapture(cmd, args) {
  const result = spawnSync(cmd, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`${cmd} failed: ${result.stderr || result.stdout}`);
  }
  return result.stdout;
}

export function resolveMediaPath(filePath) {
  if (!filePath) return filePath;
  if (fs.existsSync(filePath)) return filePath;
  const fromRel = fromRepoRelative(filePath);
  if (fs.existsSync(fromRel)) return fromRel;
  return filePath;
}

export function probeDurationMs(filePath) {
  const resolved = resolveMediaPath(filePath);
  const out = runMediaCapture(ffprobeBin(), [
    '-v',
    'error',
    '-show_entries',
    'format=duration',
    '-of',
    'default=noprint_wrappers=1:nokey=1',
    resolved,
  ]);
  return Math.round(parseFloat(out.trim()) * 1000);
}

export function validateWav(filePath) {
  const resolved = resolveMediaPath(filePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`WAV not found: ${resolved}`);
  }
  if (fs.statSync(resolved).size < 44) {
    throw new Error(`WAV file is empty or truncated: ${resolved}`);
  }
  probeDurationMs(resolved);
  return resolved;
}
