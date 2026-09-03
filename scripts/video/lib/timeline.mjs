import { VHS_SETTINGS, sleepMs, REPO_ROOT } from './paths.mjs';
import path from 'node:path';

const DEFAULTS = {
  pauseAfterNarrationMs: 300,
  pauseAfterCommandMs: 500,
  pauseAfterOutputMs: 800,
  commentPauseMs: 500,
};

function typingDurationMs(text, typingSpeedMs) {
  if (!text) return 0;
  return text.length * typingSpeedMs;
}

function narrationMap(segments) {
  const map = new Map();
  for (const segment of segments) {
    map.set(segment.index, segment);
  }
  return map;
}

export function buildTimeline(script, synthesizedSegments, settings = {}) {
  const vhs = { ...VHS_SETTINGS, ...(script.vhs || {}) };
  const opts = { ...DEFAULTS, ...(script.timing || {}), ...(settings.timing || {}) };
  const narrations = narrationMap(synthesizedSegments);

  let cursorMs = 0;
  const audioEvents = [];
  const vhsEvents = [];

  const pushSleep = (ms) => {
    if (ms > 0) vhsEvents.push({ kind: 'sleep', ms });
    cursorMs += ms;
  };

  const pushType = (text, hidden = false) => {
    vhsEvents.push({ kind: 'type', text, hidden });
    // VHS types during Type — duration is the typing time, not a separate Sleep.
    return typingDurationMs(text, vhs.typingSpeedMs);
  };

  const pushEnter = () => {
    vhsEvents.push({ kind: 'enter' });
  };

  for (const [index, step] of script.steps.entries()) {
    const narration = narrations.get(index);

    if (step.hide) {
      vhsEvents.push({ kind: 'hide' });
    }

    if (Array.isArray(step.commands)) {
      for (const command of step.commands) {
        cursorMs += pushType(command, Boolean(step.hide));
        pushEnter();
        pushSleep(opts.pauseAfterCommandMs);
      }
    }

    if (step.show) {
      vhsEvents.push({ kind: 'show' });
    }

    if (step.comment) {
      cursorMs += pushType(step.comment);
      pushEnter();
      pushSleep(opts.commentPauseMs);
    }

    if (narration) {
      audioEvents.push({
        startMs: cursorMs,
        durationMs: narration.durationMs,
        text: narration.text,
        wavPath: narration.wavPath,
        stepIndex: index,
      });
      pushSleep(narration.durationMs + opts.pauseAfterNarrationMs);
    }

    if (step.command) {
      cursorMs += pushType(step.command);
      pushEnter();
      const outputWait = step.pauseAfter ?? step.pause ?? opts.pauseAfterOutputMs;
      pushSleep(outputWait);
    } else if (step.pauseAfter ?? step.pause) {
      pushSleep(step.pauseAfter ?? step.pause);
    }
  }

  return {
    vhs,
    audioEvents,
    vhsEvents,
    totalDurationMs: cursorMs,
  };
}

/** Scale audio markers to match actual VHS duration (estimated typing often runs long). */
export function calibrateAudioEvents(audioEvents, estimatedDurationMs, actualDurationMs) {
  if (!audioEvents.length || !estimatedDurationMs || !actualDurationMs) {
    return audioEvents;
  }
  const scale = actualDurationMs / estimatedDurationMs;
  if (Math.abs(scale - 1) < 0.02) {
    return audioEvents;
  }
  return audioEvents.map((event) => ({
    ...event,
    startMs: Math.round(event.startMs * scale),
  }));
}

export function audioTimelineEndMs(audioEvents) {
  if (!audioEvents.length) return 0;
  return Math.max(...audioEvents.map((event) => event.startMs + event.durationMs));
}

export function renderVhsTape(id, timeline, assetDir) {
  const { vhs, vhsEvents } = timeline;
  const lines = [];
  const outBase = relFromRepo(assetDir);

  lines.push(`Output ${outBase}/terminal.mp4`);
  lines.push(`Output ${outBase}/terminal.gif`);
  lines.push('');
  lines.push(`Set Shell "${vhs.shell}"`);
  lines.push(`Set FontSize ${vhs.fontSize}`);
  lines.push(`Set Width ${vhs.width}`);
  lines.push(`Set Height ${vhs.height}`);
  lines.push(`Set Theme "${vhs.theme}"`);
  lines.push(`Set TypingSpeed ${vhs.typingSpeedMs}ms`);
  lines.push(`Set Framerate ${vhs.framerate}`);
  lines.push('');

  let hidden = false;
  for (const event of vhsEvents) {
    switch (event.kind) {
      case 'hide':
        lines.push('Hide');
        hidden = true;
        break;
      case 'show':
        lines.push('Show');
        hidden = false;
        break;
      case 'type':
        if (event.hidden && !hidden) {
          lines.push('Hide');
          hidden = true;
        }
        lines.push(`Type "${escapeTape(event.text)}"`);
        break;
      case 'enter':
        lines.push('Enter');
        break;
      case 'sleep':
        lines.push(`Sleep ${sleepMs(event.ms)}`);
        break;
      default:
        break;
    }
  }

  return `${lines.join('\n')}\n`;
}

function relFromRepo(absPath) {
  return path.relative(REPO_ROOT, absPath).replace(/\\/g, '/');
}

function escapeTape(text) {
  return text.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}
