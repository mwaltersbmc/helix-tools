import fs from 'node:fs';
import { MANIFEST_PATH } from './paths.mjs';

export function loadManifest() {
  return JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
}

export function resolveUseCaseIds(requestedIds) {
  const manifest = loadManifest();
  const cases = manifest.useCases || [];

  if (requestedIds.length > 0) {
    return requestedIds.map((id) => {
      const uc = cases.find((entry) => entry.id === id);
      if (!uc) {
        throw new Error(`Use case not found in manifest: ${id}`);
      }
      return uc;
    });
  }

  return cases.filter((uc) => uc.video?.enabled);
}

export function videoConfig(useCase) {
  const video = useCase.video || {};
  return {
    id: useCase.id,
    script: video.script || useCase.id,
    voice: video.voice,
    enabled: Boolean(video.enabled),
  };
}
