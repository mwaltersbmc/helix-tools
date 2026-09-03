import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = path.resolve(here, '../../..');
export const MANIFEST_PATH = path.join(REPO_ROOT, 'docs/hitt/use-cases.json');
export const SCRIPTS_DIR = path.join(REPO_ROOT, 'docs/videos/scripts');
export const VOICES_PATH = path.join(REPO_ROOT, 'azure/voices.yaml');
export const ASSETS_DIR = path.join(REPO_ROOT, 'docs/assets/videos');
export const VHS_SETTINGS = {
  shell: 'bash',
  fontSize: 16,
  width: 1200,
  height: 676,
  theme: 'Catppuccin Mocha',
  typingSpeedMs: 60,
  framerate: 30,
};

export function scriptDir(id) {
  return path.join(SCRIPTS_DIR, id);
}

export function scriptPath(id) {
  return path.join(scriptDir(id), 'script.yaml');
}

export function assetDir(id) {
  return path.join(ASSETS_DIR, id);
}

export function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

export function readText(filePath) {
  return fs.readFileSync(filePath, 'utf8');
}

export function writeText(filePath, content) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, content, 'utf8');
}

export function msToVttTime(ms) {
  const totalSeconds = Math.max(0, ms) / 1000;
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = Math.floor(totalSeconds % 60);
  const millis = Math.round((totalSeconds % 1) * 1000);
  return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}.${String(millis).padStart(3, '0')}`;
}

export function escapeXml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

export function sleepMs(ms) {
  return `${Math.max(0, Math.round(ms))}ms`;
}

export function toRepoRelative(absPath) {
  return path.relative(REPO_ROOT, absPath).split(path.sep).join('/');
}

export function fromRepoRelative(relPath) {
  return path.resolve(REPO_ROOT, relPath);
}

export function isWsl() {
  try {
    return fs.readFileSync('/proc/version', 'utf8').toLowerCase().includes('microsoft');
  } catch {
    return false;
  }
}

export function wordCount(text) {
  return text.trim().split(/\s+/).filter(Boolean).length;
}
