#!/usr/bin/env node
/**
 * Render HITT use-case videos: script.yaml → Azure TTS → VHS → mux + captions.
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  REPO_ROOT,
  assetDir,
  ensureDir,
  scriptPath,
  toRepoRelative,
  writeText,
} from './lib/paths.mjs';
import { loadScript, validateScript, flattenNarrationSteps } from './lib/script.mjs';
import { synthesizeSegments } from './lib/azure-tts.mjs';
import { buildTimeline, renderVhsTape, calibrateAudioEvents, audioTimelineEndMs } from './lib/timeline.mjs';
import { resolveUseCaseIds, videoConfig } from './lib/manifest.mjs';
import { writeCaptions } from './lib/captions.mjs';
import {
  buildNarrationTrack,
  muxVideoAudioCaptions,
  probeDurationMs,
  regenerateGif,
} from './lib/assemble.mjs';

function loadDotEnv() {
  const envPath = path.join(REPO_ROOT, '.env');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }
}

function usage() {
  console.log(`Usage: node scripts/video/render.mjs [options] [use-case-id ...]

  No arguments  — render every use case with video.enabled == true
  With IDs      — render only those use cases

Options:
  --validate    Validate scripts only (no Azure / VHS / ffmpeg)
  --tts-only    Synthesize narration audio only
  --vhs-only    Build tape + run VHS only (skip TTS and mux)
  --skip-vhs    Reuse existing terminal.mp4 (skip VHS re-record)
  --native      Use native vhs on the host (default: Docker)
  --no-burn     Skip burned-in captions (still writes .vtt / .srt)
  -h, --help    Show this help

Environment:
  AZURE_SPEECH_KEY, AZURE_SPEECH_REGION  — required for full render / --tts-only
  VHS_DOCKER=0, VHS_FORCE_NATIVE=1        — same as --native

Examples:
  npm run video:validate -- info-cluster-status
  npm run video:render -- info-cluster-status
  npm run video:render
`);
}

function parseArgs(argv) {
  const options = {
    validateOnly: false,
    ttsOnly: false,
    vhsOnly: false,
    skipVhs: false,
    native: false,
    burnCaptions: true,
    ids: [],
  };

  for (const arg of argv) {
    switch (arg) {
      case '-h':
      case '--help':
        usage();
        process.exit(0);
        break;
      case '--validate':
        options.validateOnly = true;
        break;
      case '--tts-only':
        options.ttsOnly = true;
        break;
      case '--vhs-only':
        options.vhsOnly = true;
        break;
      case '--skip-vhs':
        options.skipVhs = true;
        break;
      case '--native':
        options.native = true;
        break;
      case '--no-burn':
        options.burnCaptions = false;
        break;
      default:
        if (arg.startsWith('-')) {
          console.error(`Unknown option: ${arg}`);
          usage();
          process.exit(1);
        }
        options.ids.push(arg);
        break;
    }
  }

  if (process.env.VHS_DOCKER === '0' || process.env.VHS_FORCE_NATIVE === '1') {
    options.native = true;
  }

  return options;
}

function runVhs(tapePath, native) {
  const relTape = toRepoRelative(tapePath);
  const args = native
    ? ['scripts/video/run-vhs.sh', '--native', relTape]
    : ['scripts/video/run-vhs.sh', relTape];
  const result = spawnSync('bash', args, {
    cwd: REPO_ROOT,
    stdio: 'inherit',
  });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

async function renderOne(useCase, options) {
  const config = videoConfig(useCase);
  const scriptId = config.script;
  const outDir = assetDir(config.id);
  ensureDir(outDir);

  console.log(`\n==> ${config.id} (script: ${scriptId})`);

  if (!fs.existsSync(scriptPath(scriptId))) {
    throw new Error(`Missing script: ${scriptPath(scriptId)}`);
  }

  const script = loadScript(scriptId);
  const validation = validateScript(script);

  for (const warning of validation.warnings) {
    console.warn(`warning: ${warning}`);
  }
  if (validation.errors.length > 0) {
    throw new Error(validation.errors.join('\n'));
  }

  if (options.validateOnly) {
    console.log('valid');
    return;
  }

  const voiceId = config.voice || script.voice;
  const locale = script.locale || 'en-GB';
  const narrationSteps = flattenNarrationSteps(script);

  let synthesized = [];
  const segmentsDir = path.join(outDir, 'segments');

  if (!options.vhsOnly) {
    console.log('Synthesizing narration (Azure Speech) ...');
    synthesized = await synthesizeSegments(narrationSteps, {
      voiceId,
      locale,
      outputDir: segmentsDir,
    });
    for (const segment of synthesized) {
      console.log(`  step ${segment.index}: ${segment.durationMs}ms — ${segment.text.slice(0, 60)}...`);
    }
  } else if (fs.existsSync(path.join(segmentsDir, 'segments.json'))) {
    synthesized = JSON.parse(fs.readFileSync(path.join(segmentsDir, 'segments.json'), 'utf8'));
    console.log('Using existing narration segments (delete segments/ to re-synthesize)');
  } else {
    synthesized = narrationSteps.map((step) => ({
      ...step,
      durationMs: Math.max(1500, step.text.split(/\s+/).length * 350),
      wavPath: null,
    }));
  }

  if (options.ttsOnly) {
    console.log(`TTS written to ${segmentsDir}`);
    return;
  }

  const timeline = buildTimeline(script, synthesized);
  const tapeContent = renderVhsTape(config.id, timeline, outDir);
  const tapePath = path.join(outDir, `${config.id}.tape`);
  writeText(tapePath, tapeContent);

  const terminalMp4 = path.join(outDir, 'terminal.mp4');

  if (options.skipVhs && fs.existsSync(terminalMp4)) {
    console.log(`Reusing ${toRepoRelative(terminalMp4)} (--skip-vhs)`);
  } else {
    console.log('Recording terminal (VHS) ...');
    runVhs(tapePath, options.native);
  }

  if (!fs.existsSync(terminalMp4)) {
    throw new Error(`VHS did not produce ${terminalMp4}`);
  }

  if (options.vhsOnly) {
    console.log(`Terminal recording: ${terminalMp4}`);
    return;
  }

  const narrationWav = path.join(outDir, 'narration.wav');
  const terminalDurationMs = probeDurationMs(terminalMp4);
  const audioEvents = calibrateAudioEvents(
    timeline.audioEvents,
    timeline.totalDurationMs,
    terminalDurationMs,
  );
  const audioEndMs = audioTimelineEndMs(audioEvents);
  const bedDurationMs = Math.max(terminalDurationMs, audioEndMs + 300);

  if (timeline.audioEvents.length > 0) {
    const scale = terminalDurationMs / timeline.totalDurationMs;
    console.log(
      `  sync: terminal ${terminalDurationMs}ms, estimated ${timeline.totalDurationMs}ms, scale ${scale.toFixed(3)}`,
    );
    for (const event of audioEvents) {
      console.log(`  narration @ ${event.startMs}ms for ${event.durationMs}ms`);
    }
  }

  console.log('Building narration track ...');
  buildNarrationTrack(audioEvents, narrationWav, bedDurationMs);

  writeCaptions(config.id, outDir, audioEvents);

  const srtPath = path.join(outDir, `${config.id}.srt`);
  console.log('Muxing video + audio + captions ...');
  const finalMp4 = muxVideoAudioCaptions({
    id: config.id,
    assetDir: outDir,
    terminalMp4,
    narrationWav,
    srtPath,
    burnCaptions: options.burnCaptions,
  });

  regenerateGif(config.id, outDir);

  console.log('Outputs:');
  console.log(`  ${finalMp4}`);
  console.log(`  ${path.join(outDir, `${config.id}.gif`)}`);
  console.log(`  ${path.join(outDir, `${config.id}.vtt`)}`);
  console.log(`  ${path.join(outDir, `${config.id}.srt`)}`);
}

async function main() {
  loadDotEnv();
  const options = parseArgs(process.argv.slice(2));
  const useCases = resolveUseCaseIds(options.ids);

  if (useCases.length === 0) {
    console.error('No use cases selected. Enable video.enabled in use-cases.json or pass IDs.');
    process.exit(1);
  }

  for (const useCase of useCases) {
    await renderOne(useCase, options);
  }

  console.log('\nDone.');
}

main().catch((error) => {
  console.error(`error: ${error.message}`);
  process.exit(1);
});
