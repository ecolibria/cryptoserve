/**
 * Professional CLI styling for CryptoServe.
 *
 * Provides consistent, enterprise-grade terminal output styling.
 * Port of sdk/python/cryptoserve/_cli_style.py — zero dependencies.
 */

import { env, stdout } from 'node:process';

function supportsColor() {
  if (env.NO_COLOR) return false;
  if (env.FORCE_COLOR) return true;
  if (!stdout.isTTY) return false;
  if (process.platform === 'win32') {
    return env.TERM === 'xterm' || !!env.ANSICON;
  }
  return true;
}

const ENABLED = supportsColor();
const e = (code) => ENABLED ? code : '';

export const Colors = {
  RESET:          e('\x1b[0m'),
  BLACK:          e('\x1b[30m'),
  RED:            e('\x1b[31m'),
  GREEN:          e('\x1b[32m'),
  YELLOW:         e('\x1b[33m'),
  BLUE:           e('\x1b[34m'),
  MAGENTA:        e('\x1b[35m'),
  CYAN:           e('\x1b[36m'),
  WHITE:          e('\x1b[37m'),
  BRIGHT_BLACK:   e('\x1b[90m'),
  BRIGHT_RED:     e('\x1b[91m'),
  BRIGHT_GREEN:   e('\x1b[92m'),
  BRIGHT_YELLOW:  e('\x1b[93m'),
  BRIGHT_BLUE:    e('\x1b[94m'),
  BRIGHT_MAGENTA: e('\x1b[95m'),
  BRIGHT_CYAN:    e('\x1b[96m'),
  BRIGHT_WHITE:   e('\x1b[97m'),
  BOLD:           e('\x1b[1m'),
  DIM:            e('\x1b[2m'),
  ITALIC:         e('\x1b[3m'),
  UNDERLINE:      e('\x1b[4m'),
};

export const Style = {
  SUCCESS:   Colors.BRIGHT_GREEN,
  ERROR:     Colors.BRIGHT_RED,
  WARNING:   Colors.BRIGHT_YELLOW,
  INFO:      Colors.BRIGHT_BLUE,
  HEADER:    Colors.BRIGHT_CYAN + Colors.BOLD,
  SUBHEADER: Colors.CYAN,
  LABEL:     Colors.BRIGHT_WHITE + Colors.BOLD,
  VALUE:     Colors.WHITE,
  DIM:       Colors.BRIGHT_BLACK,
  ACCENT:    Colors.BRIGHT_MAGENTA,
  RESET:     Colors.RESET,
};

export const Box = {
  TOP_LEFT:     '╭',
  TOP_RIGHT:    '╮',
  BOTTOM_LEFT:  '╰',
  BOTTOM_RIGHT: '╯',
  HORIZONTAL:   '─',
  VERTICAL:     '│',
  T_DOWN:       '┬',
  T_UP:         '┴',
  T_RIGHT:      '├',
  T_LEFT:       '┤',
  CROSS:        '┼',
  DOUBLE_HORIZONTAL: '═',
  DOUBLE_VERTICAL:   '║',
};

export const Icons = {
  SUCCESS:      '+',
  ERROR:        'x',
  WARNING:      '!',
  INFO:         '*',
  PENDING:      'o',
  IN_PROGRESS:  '-',
  ARROW_RIGHT:  '>',
  ARROW_LEFT:   '<',
  BULLET:       '-',
  STAR:         '*',
  LOCK:         '[locked]',
  UNLOCK:       '[unlocked]',
  KEY:          '[key]',
  SHIELD:       '[secure]',
  CHECK:        '[x]',
  ROCKET:       '[deploy]',
  CLOCK:        '[time]',
  LINK:         '[link]',
};

export function header(text, width = 60) {
  const pad = width - 4;
  const centered = text.length >= pad
    ? text.slice(0, pad)
    : ' '.repeat(Math.floor((pad - text.length) / 2)) + text +
      ' '.repeat(Math.ceil((pad - text.length) / 2));
  return [
    `${Style.HEADER}${Box.TOP_LEFT}${Box.HORIZONTAL.repeat(width - 2)}${Box.TOP_RIGHT}${Style.RESET}`,
    `${Style.HEADER}${Box.VERTICAL}${Style.RESET} ${centered} ${Style.HEADER}${Box.VERTICAL}${Style.RESET}`,
    `${Style.HEADER}${Box.BOTTOM_LEFT}${Box.HORIZONTAL.repeat(width - 2)}${Box.BOTTOM_RIGHT}${Style.RESET}`,
  ].join('\n');
}

export function compactHeader(command = '') {
  if (command) {
    return `\n${Style.HEADER}CRYPTOSERVE${Style.RESET} ${Style.DIM}›${Style.RESET} ${Style.LABEL}${command}${Style.RESET}\n`;
  }
  return `\n${Style.HEADER}CRYPTOSERVE${Style.RESET}\n`;
}

export function subheader(text, width = 60) {
  const line = Box.HORIZONTAL.repeat(width);
  return `\n${Style.SUBHEADER}${line}\n  ${text}\n${line}${Style.RESET}`;
}

export function section(title) {
  return `\n${Style.LABEL}${title}${Style.RESET}`;
}

export function divider(width = 60, char = '─') {
  return `${Style.DIM}${char.repeat(width)}${Style.RESET}`;
}

export function success(text) {
  return `${Style.SUCCESS}${Icons.SUCCESS}${Style.RESET} ${text}`;
}

export function error(text) {
  return `${Style.ERROR}${Icons.ERROR}${Style.RESET} ${text}`;
}

export function warning(text) {
  return `${Style.WARNING}${Icons.WARNING}${Style.RESET}  ${text}`;
}

export function info(text) {
  return `${Style.INFO}${Icons.INFO}${Style.RESET}  ${text}`;
}

export function dim(text) {
  return `${Style.DIM}${text}${Style.RESET}`;
}

export function bold(text) {
  return `${Colors.BOLD}${text}${Style.RESET}`;
}

export function labelValue(label, value, labelWidth = 20) {
  return `  ${Style.LABEL}${label.padEnd(labelWidth)}${Style.RESET} ${Style.VALUE}${value}${Style.RESET}`;
}

export function tableRow(columns, widths) {
  const parts = columns.map((col, i) =>
    String(col).padEnd(widths[i]).slice(0, widths[i])
  );
  return `  ${parts.join(' ')}`;
}

export function tableHeader(columns, widths) {
  const headerLine = tableRow(columns, widths);
  const underline = '  ' + widths.map(w => Box.HORIZONTAL.repeat(w)).join(' ');
  return `${Style.LABEL}${headerLine}${Style.RESET}\n${Style.DIM}${underline}${Style.RESET}`;
}

export function progressBar(current, total, width = 30, showPercent = true) {
  const percent = total === 0 ? 100 : Math.floor((current / total) * 100);
  const filled = Math.floor((current / Math.max(total, 1)) * width);
  const empty = width - filled;
  const bar = '█'.repeat(filled) + '░'.repeat(empty);
  const color = percent >= 80 ? Style.SUCCESS : percent >= 50 ? Style.WARNING : Style.ERROR;
  return showPercent
    ? `${color}${bar}${Style.RESET} ${percent}%`
    : `${color}${bar}${Style.RESET}`;
}

export function statusBadge(status) {
  const lower = status.toLowerCase();
  if (['ready', 'active', 'success', 'healthy', 'ok'].includes(lower)) {
    return `${Style.SUCCESS}● ${status}${Style.RESET}`;
  }
  if (['pending', 'waiting', 'in_progress'].includes(lower)) {
    return `${Style.WARNING}○ ${status}${Style.RESET}`;
  }
  if (['error', 'failed', 'blocked'].includes(lower)) {
    return `${Style.ERROR}● ${status}${Style.RESET}`;
  }
  return `${Style.DIM}○ ${status}${Style.RESET}`;
}

export function codeBlock(code) {
  const lines = code.trim().split('\n');
  const formatted = [];
  formatted.push(`${Style.DIM}┌${'─'.repeat(58)}┐${Style.RESET}`);
  for (const line of lines) {
    formatted.push(`${Style.DIM}│${Style.RESET} ${Style.ACCENT}${line.padEnd(56)}${Style.RESET} ${Style.DIM}│${Style.RESET}`);
  }
  formatted.push(`${Style.DIM}└${'─'.repeat(58)}┘${Style.RESET}`);
  return formatted.join('\n');
}

export function brandHeader() {
  return `
${Style.HEADER}╭────────────────────────────────────────────────────────╮
│                                                        │
│   ${Colors.BRIGHT_WHITE}CRYPTOSERVE${Style.HEADER}                                        │
│   ${Style.DIM}Enterprise Cryptography Platform${Style.HEADER}                    │
│                                                        │
╰────────────────────────────────────────────────────────╯${Style.RESET}
`;
}
