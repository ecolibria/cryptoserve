/**
 * Project initialization for CryptoServe.
 *
 * `cryptoserve init` sets up:
 * 1. Master key generation + OS keychain storage
 * 2. AI tool protection (block .env from AI context — secretless-ai pattern)
 * 3. Project configuration file
 *
 * Idempotent — safe to run multiple times.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import {
  generateMasterKey,
  storeMasterKey,
  loadMasterKey,
  isKeychainAvailable,
  promptPassword,
} from './keychain.mjs';

const MARKER = '<!-- cryptoserve:managed -->';
const CONFIG_DIR = join(homedir(), '.cryptoserve');

// ---------------------------------------------------------------------------
// AI tool detection (borrowed from secretless-ai)
// ---------------------------------------------------------------------------

const AI_TOOLS = [
  { name: 'Claude Code',  markers: ['.claude', 'CLAUDE.md'],           hasHooks: true },
  { name: 'Cursor',       markers: ['.cursor', '.cursorrules'],        hasHooks: false },
  { name: 'Copilot',      markers: ['.github/copilot-instructions.md'], hasHooks: false },
  { name: 'Windsurf',     markers: ['.windsurf', '.windsurfrules'],    hasHooks: false },
  { name: 'Cline',        markers: ['.cline', '.clinerules'],          hasHooks: false },
  { name: 'Aider',        markers: ['.aider', '.aiderignore'],         hasHooks: false },
];

const SECRET_FILE_PATTERNS = [
  '.env', '.env.local', '.env.*',
  '*.key', '*.pem', '*.p12', '*.pfx', '*.crt',
  '.aws/credentials', '.ssh/*', '.docker/config.json',
  '.git-credentials', '.npmrc', '.pypirc',
  '*.tfstate', '*.tfvars',
  'secrets/', 'credentials/',
];

function detectAiTools(projectDir) {
  const detected = [];
  for (const tool of AI_TOOLS) {
    for (const marker of tool.markers) {
      if (existsSync(join(projectDir, marker))) {
        detected.push(tool);
        break;
      }
    }
  }
  return detected;
}

// ---------------------------------------------------------------------------
// AI tool protection setup
// ---------------------------------------------------------------------------

function buildSecretlessInstructions() {
  const patterns = SECRET_FILE_PATTERNS.map(p => `- \`${p}\``).join('\n');
  return `

${MARKER}
## CryptoServe Security

**Blocked file patterns** (never read or reference):
${patterns}

**If you need a credential:**
1. Reference via \`$VAR_NAME\` in shell commands
2. Never hardcode credentials in source files
3. Use \`cryptoserve vault run -- <command>\` to inject secrets at runtime
`;
}

function protectClaudeCode(projectDir, result) {
  // 1. Add deny rules to .claude/settings.json
  const claudeDir = join(projectDir, '.claude');
  if (!existsSync(claudeDir)) mkdirSync(claudeDir, { recursive: true });

  const settingsPath = join(claudeDir, 'settings.json');
  let settings = {};
  if (existsSync(settingsPath)) {
    try { settings = JSON.parse(readFileSync(settingsPath, 'utf-8')); }
    catch { settings = {}; }
  }

  if (!settings.permissions) settings.permissions = {};
  if (!Array.isArray(settings.permissions.deny)) settings.permissions.deny = [];

  const denyRules = [
    'Read(.env*)', 'Read(*.key)', 'Read(*.pem)', 'Read(*.p12)',
    'Grep(.env*)', 'Glob(.env*)',
    'Bash(cat .env*)', 'Bash(head .env*)', 'Bash(tail .env*)',
  ];
  for (const rule of denyRules) {
    if (!settings.permissions.deny.includes(rule)) {
      settings.permissions.deny.push(rule);
    }
  }

  writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
  result.filesModified.push('.claude/settings.json');

  // 2. Add instructions to CLAUDE.md
  addInstructions(join(projectDir, 'CLAUDE.md'), result);
}

function protectCursor(projectDir, result) {
  addInstructions(join(projectDir, '.cursorrules'), result);
}

function protectCopilot(projectDir, result) {
  const dir = join(projectDir, '.github');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  addInstructions(join(dir, 'copilot-instructions.md'), result);
}

function protectWindsurf(projectDir, result) {
  addInstructions(join(projectDir, '.windsurfrules'), result);
}

function protectCline(projectDir, result) {
  addInstructions(join(projectDir, '.clinerules'), result);
}

function protectAider(projectDir, result) {
  const aiderIgnore = join(projectDir, '.aiderignore');
  let content = existsSync(aiderIgnore) ? readFileSync(aiderIgnore, 'utf-8') : '';
  if (content.includes(MARKER)) return;

  const patterns = SECRET_FILE_PATTERNS.join('\n');
  content += `\n# ${MARKER}\n${patterns}\n`;
  writeFileSync(aiderIgnore, content);
  result.filesModified.push('.aiderignore');
}

function addInstructions(filePath, result) {
  let content = existsSync(filePath) ? readFileSync(filePath, 'utf-8') : '';
  if (content.includes(MARKER)) return;

  content += buildSecretlessInstructions();
  writeFileSync(filePath, content);

  const existed = existsSync(filePath);
  if (existed) {
    result.filesModified.push(filePath);
  } else {
    result.filesCreated.push(filePath);
  }
}

const PROTECTORS = {
  'Claude Code': protectClaudeCode,
  'Cursor': protectCursor,
  'Copilot': protectCopilot,
  'Windsurf': protectWindsurf,
  'Cline': protectCline,
  'Aider': protectAider,
};

// ---------------------------------------------------------------------------
// Main init function
// ---------------------------------------------------------------------------

export async function initProject(projectDir, options = {}) {
  const result = {
    toolsDetected: [],
    toolsConfigured: [],
    filesCreated: [],
    filesModified: [],
    keyStorage: null,
    secretsWarning: 0,
  };

  // 1. Ensure config directory
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }

  // 2. Generate or load master key
  let existingKey = null;
  try { existingKey = await loadMasterKey(); } catch { /* not found */ }

  if (!existingKey) {
    const keyBase64 = await generateMasterKey();
    const keychainOk = await isKeychainAvailable();

    if (keychainOk && !options.insecureStorage) {
      result.keyStorage = await storeMasterKey(keyBase64, { useKeychain: true });
    } else if (options.insecureStorage) {
      // Plaintext fallback (requires explicit opt-in)
      writeFileSync(
        join(CONFIG_DIR, 'master.key'),
        keyBase64,
        { mode: 0o600 }
      );
      result.keyStorage = { storage: 'plaintext-file', path: join(CONFIG_DIR, 'master.key') };
    } else {
      // Encrypted file with password
      const pw = await promptPassword('Set vault password (for encrypted key storage): ');
      result.keyStorage = await storeMasterKey(keyBase64, {
        useKeychain: false,
        fallbackPassword: pw,
      });
    }
  } else {
    result.keyStorage = { storage: 'existing' };
  }

  // 3. Detect and protect AI tools
  const detected = detectAiTools(projectDir);
  result.toolsDetected = detected.map(t => t.name);

  for (const tool of detected) {
    const protector = PROTECTORS[tool.name];
    if (protector) {
      protector(projectDir, result);
      result.toolsConfigured.push(tool.name);
    }
  }

  // 4. Create project config
  const configPath = join(projectDir, '.cryptoserve.json');
  if (!existsSync(configPath)) {
    writeFileSync(configPath, JSON.stringify({
      version: 1,
      project: projectDir.split('/').pop(),
      createdAt: new Date().toISOString(),
    }, null, 2));
    result.filesCreated.push('.cryptoserve.json');
  }

  return result;
}
