import fs from 'node:fs';
import path from 'node:path';
import { ensureDir } from './paths.mjs';
import {
  ffmpegBin,
  OUTPUT_SAMPLE_RATE,
  probeDurationMs,
  resolveMediaPath,
  runMedia,
  validateWav,
} from './media.mjs';

export { validateWav, probeDurationMs, resolveMediaPath, OUTPUT_SAMPLE_RATE } from './media.mjs';

function buildSingleSegmentTrack(ffmpeg, event, outputPath, durationSec) {
  const totalSamples = Math.round(durationSec * OUTPUT_SAMPLE_RATE);
  runMedia(
    ffmpeg,
    [
      '-i',
      event.wavPath,
      '-af',
      `aresample=${OUTPUT_SAMPLE_RATE},adelay=${event.startMs}|${event.startMs},apad=whole_len=${totalSamples}`,
      '-ar',
      String(OUTPUT_SAMPLE_RATE),
      '-ac',
      '1',
      '-y',
      outputPath,
    ],
    `ffmpeg: place narration at ${event.startMs}ms (${path.basename(event.wavPath)})`,
  );
}

function buildMultiSegmentTrack(ffmpeg, events, outputPath, durationSec) {
  const args = [
    '-f',
    'lavfi',
    '-i',
    `anullsrc=r=${OUTPUT_SAMPLE_RATE}:cl=mono`,
    '-t',
    String(durationSec),
  ];

  for (const event of events) {
    args.push('-i', event.wavPath);
  }

  const delayFilters = events
    .map(
      (event, i) =>
        `[${i + 1}:a]aresample=${OUTPUT_SAMPLE_RATE},adelay=${event.startMs}|${event.startMs}[d${i}]`,
    )
    .join(';');

  const mixInputs = ['[0:a]', ...events.map((_, i) => `[d${i}]`)].join('');
  const filter = `${delayFilters};${mixInputs}amix=inputs=${events.length + 1}:duration=first:dropout_transition=0:normalize=0[aout]`;

  runMedia(
    ffmpeg,
    [...args, '-filter_complex', filter, '-map', '[aout]', '-ar', String(OUTPUT_SAMPLE_RATE), '-y', outputPath],
    `ffmpeg: mix ${events.length} narration segments`,
  );
}

export function buildNarrationTrack(audioEvents, outputPath, totalDurationMs) {
  ensureDir(path.dirname(outputPath));
  const durationSec = Math.max(1, totalDurationMs / 1000);
  const ffmpeg = ffmpegBin();

  const events = audioEvents.map((event) => ({
    ...event,
    wavPath: validateWav(event.wavPath),
  }));

  if (events.length === 0) {
    runMedia(
      ffmpeg,
      [
        '-f',
        'lavfi',
        '-i',
        `anullsrc=r=${OUTPUT_SAMPLE_RATE}:cl=mono`,
        '-t',
        String(durationSec),
        '-ar',
        String(OUTPUT_SAMPLE_RATE),
        '-y',
        outputPath,
      ],
      'ffmpeg: silent narration bed',
    );
    return outputPath;
  }

  if (events.length === 1) {
    buildSingleSegmentTrack(ffmpeg, events[0], outputPath, durationSec);
    return outputPath;
  }

  buildMultiSegmentTrack(ffmpeg, events, outputPath, durationSec);
  return outputPath;
}

export function muxVideoAudioCaptions({
  id,
  assetDir,
  terminalMp4,
  narrationWav,
  srtPath,
  burnCaptions = true,
}) {
  const ffmpeg = ffmpegBin();
  const finalMp4 = path.join(assetDir, `${id}.mp4`);
  const tempMp4 = path.join(assetDir, `${id}.mux.mp4`);
  const terminal = resolveMediaPath(terminalMp4);
  const narration = resolveMediaPath(narrationWav);
  const terminalMs = probeDurationMs(terminal);
  const narrationMs = probeDurationMs(narration);
  const outputMs = Math.max(terminalMs, narrationMs);
  const outputSec = outputMs / 1000;
  const padVideoSec = Math.max(0, (outputMs - terminalMs) / 1000);

  const filter =
    padVideoSec > 0.01
      ? `[0:v]tpad=stop_mode=clone:stop_duration=${padVideoSec.toFixed(3)}[vout];[1:a]aresample=${OUTPUT_SAMPLE_RATE}[aout]`
      : `[1:a]aresample=${OUTPUT_SAMPLE_RATE}[aout]`;

  const maps =
    padVideoSec > 0.01
      ? ['-map', '[vout]', '-map', '[aout]']
      : ['-map', '0:v:0', '-map', '[aout]'];

  runMedia(
    ffmpeg,
    [
      '-i',
      terminal,
      '-i',
      narration,
      '-filter_complex',
      filter,
      ...maps,
      '-c:v',
      'libx264',
      '-preset',
      'veryfast',
      '-crf',
      '18',
      '-c:a',
      'aac',
      '-ar',
      String(OUTPUT_SAMPLE_RATE),
      '-b:a',
      '192k',
      '-t',
      String(outputSec),
      '-y',
      tempMp4,
    ],
    padVideoSec > 0.01
      ? `ffmpeg: mux + hold last frame ${padVideoSec.toFixed(1)}s for narration tail`
      : 'ffmpeg: mux terminal video + narration',
  );

  if (burnCaptions && fs.existsSync(srtPath)) {
    const escaped = resolveMediaPath(srtPath).replace(/\\/g, '/').replace(/:/g, '\\:');
    runMedia(
      ffmpeg,
      [
        '-i',
        tempMp4,
        '-vf',
        `subtitles='${escaped}':force_style='FontName=DejaVu Sans,FontSize=22,PrimaryColour=&HFFFFFF&,OutlineColour=&H000000&,BorderStyle=3,Outline=2,Shadow=0,MarginV=24'`,
        '-c:a',
        'copy',
        '-y',
        finalMp4,
      ],
      'ffmpeg: burn captions',
    );
    fs.unlinkSync(tempMp4);
  } else {
    fs.renameSync(tempMp4, finalMp4);
  }

  return finalMp4;
}

export function regenerateGif(id, assetDir) {
  const ffmpeg = ffmpegBin();
  const mp4 = resolveMediaPath(path.join(assetDir, `${id}.mp4`));
  const gif = path.join(assetDir, `${id}.gif`);
  if (!fs.existsSync(mp4)) return null;

  runMedia(
    ffmpeg,
    [
      '-i',
      mp4,
      '-vf',
      'fps=15,scale=800:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse',
      '-loop',
      '0',
      '-y',
      gif,
    ],
    'ffmpeg: regenerate gif',
  );
  return gif;
}
