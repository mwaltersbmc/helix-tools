import fs from 'node:fs';
import yaml from 'js-yaml';
import { scriptPath, wordCount } from './paths.mjs';

const MAX_NARRATION_WORDS = 25;

export function loadScript(id) {
  const file = scriptPath(id);
  if (!fs.existsSync(file)) {
    throw new Error(`Script not found: ${file}`);
  }
  const doc = yaml.load(fs.readFileSync(file, 'utf8'));
  if (!doc || typeof doc !== 'object') {
    throw new Error(`Invalid script.yaml for ${id}`);
  }
  doc.id = doc.id || id;
  return doc;
}

export function validateScript(script) {
  const errors = [];
  const warnings = [];

  if (!script.title?.trim()) {
    errors.push('title is required');
  }
  if (!Array.isArray(script.steps) || script.steps.length === 0) {
    errors.push('steps must be a non-empty array');
  }

  for (const [index, step] of (script.steps || []).entries()) {
    const label = `steps[${index}]`;

    if (step.narration) {
      const words = wordCount(step.narration);
      if (words > MAX_NARRATION_WORDS) {
        warnings.push(`${label}: narration has ${words} words (recommended max ${MAX_NARRATION_WORDS})`);
      }
    }

    if (step.command && step.command.includes('"')) {
      errors.push(`${label}: command must not contain double quotes — use single quotes for shell args`);
    }
    if (Array.isArray(step.commands)) {
      for (const cmd of step.commands) {
        if (cmd.includes('"')) {
          errors.push(`${label}: commands entry must not contain double quotes`);
        }
      }
    }
  }

  return { errors, warnings };
}

export function flattenNarrationSteps(script) {
  const segments = [];
  for (const [index, step] of script.steps.entries()) {
    if (!step.narration?.trim()) continue;
    segments.push({
      index,
      text: step.narration.trim(),
      step,
    });
  }
  return segments;
}
