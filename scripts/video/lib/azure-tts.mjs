import fs from 'node:fs';
import path from 'node:path';
import sdk from 'microsoft-cognitiveservices-speech-sdk';
import { buildSsml, resolveVoice } from './voices.mjs';
import { ensureDir, toRepoRelative } from './paths.mjs';
import { validateWav, probeDurationMs } from './media.mjs';

function azureConfig() {
  const key = process.env.AZURE_SPEECH_KEY || process.env.SPEECH_KEY;
  const region = process.env.AZURE_SPEECH_REGION || process.env.SPEECH_REGION;
  if (!key || !region) {
    throw new Error(
      'Azure Speech credentials required. Set AZURE_SPEECH_KEY and AZURE_SPEECH_REGION (see .env.example).',
    );
  }
  return { key, region };
}

export function synthesizeSsmlToFile(ssml, outputPath, { key, region }) {
  ensureDir(path.dirname(outputPath));

  return new Promise((resolve, reject) => {
    const speechConfig = sdk.SpeechConfig.fromSubscription(key, region);
    speechConfig.speechSynthesisOutputFormat =
      sdk.SpeechSynthesisOutputFormat.Riff24Khz16BitMonoPcm;

    // Write from result.audioData — more reliable than fromAudioFileOutput across WSL/Windows.
    const synthesizer = new sdk.SpeechSynthesizer(speechConfig, null);

    synthesizer.speakSsmlAsync(
      ssml,
      (result) => {
        synthesizer.close();
        if (result.reason === sdk.ResultReason.SynthesizingAudioCompleted) {
          const audio = Buffer.from(result.audioData);
          if (audio.length < 44) {
            reject(new Error('Azure Speech returned empty or invalid audio data'));
            return;
          }
          fs.writeFileSync(outputPath, audio);
          try {
            validateWav(outputPath);
          } catch (error) {
            reject(error);
            return;
          }
          resolve({
            durationMs: probeDurationMs(outputPath),
          });
        } else {
          reject(new Error(result.errorDetails || `Synthesis failed: ${result.reason}`));
        }
      },
      (error) => {
        synthesizer.close();
        reject(error);
      },
    );
  });
}

export async function synthesizeSegments(segments, { voiceId, locale, outputDir }) {
  const config = azureConfig();
  const voiceEntry = resolveVoice(voiceId);
  const results = [];

  for (const segment of segments) {
    const fileName = `narration-${String(segment.index).padStart(2, '0')}.wav`;
    const outputPath = path.join(outputDir, fileName);
    const ssml = buildSsml(segment.text, voiceEntry, locale || 'en-GB');

    const { durationMs } = await synthesizeSsmlToFile(ssml, outputPath, config);
    results.push({
      ...segment,
      wavPath: toRepoRelative(outputPath),
      durationMs,
      ssml,
    });
  }

  fs.writeFileSync(
    path.join(outputDir, 'segments.json'),
    JSON.stringify(
      results.map(({ index, text, durationMs, wavPath }) => ({
        index,
        text,
        durationMs,
        wavPath,
      })),
      null,
      2,
    ),
  );

  return results;
}
