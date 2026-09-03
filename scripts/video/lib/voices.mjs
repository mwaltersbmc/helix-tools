import fs from 'node:fs';
import yaml from 'js-yaml';
import { VOICES_PATH } from './paths.mjs';

let cached;

export function loadVoicesCatalog() {
  if (cached) return cached;
  if (!fs.existsSync(VOICES_PATH)) {
    throw new Error(`Voice catalogue not found: ${VOICES_PATH}`);
  }
  cached = yaml.load(fs.readFileSync(VOICES_PATH, 'utf8'));
  return cached;
}

export function resolveVoice(voiceId) {
  const catalog = loadVoicesCatalog();
  const id = voiceId || catalog.default;
  const entry = catalog.voices?.[id];
  if (!entry) {
    const known = Object.keys(catalog.voices || {}).join(', ');
    throw new Error(`Unknown voice '${id}'. Known voices: ${known}`);
  }
  return { id, ...entry };
}

export function buildSsml(text, voiceEntry, locale = 'en-GB') {
  const { voice, style, rate } = voiceEntry;
  let inner = text.trim().replace(/\s+/g, ' ');
  inner = inner.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  if (rate) {
    inner = `<prosody rate="${rate}">${inner}</prosody>`;
  }
  if (style) {
    inner = `<mstts:express-as style="${style}">${inner}</mstts:express-as>`;
  }

  return (
    `<speak version="1.0" xml:lang="${locale}" ` +
    `xmlns="http://www.w3.org/2001/10/synthesis" ` +
    `xmlns:mstts="https://www.w3.org/2001/mstts">` +
    `<voice name="${voice}">${inner}</voice></speak>`
  );
}
