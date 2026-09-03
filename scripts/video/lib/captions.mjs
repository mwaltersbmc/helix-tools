import { msToVttTime, writeText } from './paths.mjs';

export function buildWebVtt(audioEvents) {
  const lines = ['WEBVTT', ''];
  for (const event of audioEvents) {
    const start = msToVttTime(event.startMs);
    const end = msToVttTime(event.startMs + event.durationMs);
    lines.push(`${start} --> ${end}`);
    lines.push(event.text.replace(/\s+/g, ' ').trim());
    lines.push('');
  }
  return `${lines.join('\n')}\n`;
}

export function buildSrt(audioEvents) {
  const lines = [];
  audioEvents.forEach((event, i) => {
    const start = msToVttTime(event.startMs).replace('.', ',');
    const end = msToVttTime(event.startMs + event.durationMs).replace('.', ',');
    lines.push(String(i + 1));
    lines.push(`${start} --> ${end}`);
    lines.push(event.text.replace(/\s+/g, ' ').trim());
    lines.push('');
  });
  return `${lines.join('\n')}\n`;
}

export function writeCaptions(id, assetDir, audioEvents) {
  writeText(`${assetDir}/${id}.vtt`, buildWebVtt(audioEvents));
  writeText(`${assetDir}/${id}.srt`, buildSrt(audioEvents));
}
