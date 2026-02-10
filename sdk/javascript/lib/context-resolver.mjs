/**
 * Context-aware algorithm resolver for the CryptoServe CLI.
 *
 * Port of the 5-layer context model from the CryptoServe backend
 * (backend/app/core/algorithm_resolver.py + backend/app/schemas/context.py).
 *
 * Resolves context labels like "user-pii" to optimal algorithms from the
 * set the CLI can actually execute: AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305.
 *
 * Zero dependencies — uses only node:fs for loading .cryptoserve.json.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// =============================================================================
// Enums / Constants
// =============================================================================

const SENSITIVITY = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };

const ADVERSARIES = {
  opportunistic: 'opportunistic',
  organized_crime: 'organized_crime',
  nation_state: 'nation_state',
  insider: 'insider',
  quantum: 'quantum',
};

const USAGE = {
  at_rest: 'at_rest',
  in_transit: 'in_transit',
  in_use: 'in_use',
  streaming: 'streaming',
  disk: 'disk',
};

const FREQUENCY = { high: 'high', medium: 'medium', low: 'low', rare: 'rare' };

// Executable algorithms — what the CLI can actually do
const EXECUTABLE_ALGORITHMS = {
  'AES-256-GCM':       { keyBits: 256, securityBits: 256, hwAccelerated: true,  mode: 'gcm' },
  'AES-128-GCM':       { keyBits: 128, securityBits: 128, hwAccelerated: true,  mode: 'gcm' },
  'ChaCha20-Poly1305': { keyBits: 256, securityBits: 256, hwAccelerated: false, mode: 'stream' },
};

// Sensitivity → minimum key bits
const SENSITIVITY_MIN_BITS = {
  critical: 256,
  high: 256,
  medium: 128,
  low: 128,
};

// Sensitivity → key rotation recommendation (days)
const SENSITIVITY_ROTATION = {
  critical: 30,
  high: 90,
  medium: 180,
  low: 365,
};

// Compliance framework constraints
const COMPLIANCE_CONSTRAINTS = {
  'PCI-DSS':  { minBits: 256, maxRotationDays: 90 },
  'HIPAA':    { minBits: 256, maxRotationDays: 90 },
  'GDPR':     { minBits: 128, maxRotationDays: 365 },
  'SOX':      { minBits: 256, maxRotationDays: 180 },
  'OWASP':    { minBits: 128, maxRotationDays: 365 },
  'CCPA':     { minBits: 128, maxRotationDays: 365 },
  'NIST':     { minBits: 256, maxRotationDays: 365 },
};

// =============================================================================
// Built-in presets (ported from backend/app/main.py seed contexts)
// =============================================================================

const BUILT_IN_CONTEXTS = {
  'user-pii': {
    displayName: 'User Personal Data',
    description: 'Personally identifiable information that can identify an individual',
    sensitivity: 'high',
    compliance: ['GDPR'],
    adversaries: ['organized_crime', 'nation_state'],
    protectionYears: 20,
    usage: 'at_rest',
    frequency: 'high',
    pii: true,
    examples: ['email', 'SSN', 'phone number', 'home address', 'date of birth'],
  },
  'payment-data': {
    displayName: 'Payment & Financial',
    description: 'Payment card data and financial account information',
    sensitivity: 'critical',
    compliance: ['PCI-DSS'],
    adversaries: ['organized_crime', 'insider'],
    protectionYears: 7,
    usage: 'at_rest',
    frequency: 'high',
    pci: true,
    examples: ['credit card number', 'bank account', 'CVV', 'billing address'],
  },
  'session-tokens': {
    displayName: 'Session & Auth Tokens',
    description: 'Temporary authentication and session data',
    sensitivity: 'medium',
    compliance: ['OWASP'],
    adversaries: ['opportunistic'],
    protectionYears: 0.01,
    usage: 'in_transit',
    frequency: 'high',
    examples: ['JWT tokens', 'session IDs', 'refresh tokens', 'API keys'],
  },
  'health-data': {
    displayName: 'Health Information',
    description: 'Protected health information and medical records',
    sensitivity: 'critical',
    compliance: ['HIPAA'],
    adversaries: ['organized_crime', 'nation_state'],
    protectionYears: 25,
    usage: 'at_rest',
    frequency: 'medium',
    phi: true,
    examples: ['diagnosis', 'prescriptions', 'medical history', 'insurance ID'],
  },
  'general': {
    displayName: 'General Purpose',
    description: 'General data without specific regulatory requirements',
    sensitivity: 'medium',
    compliance: [],
    adversaries: ['opportunistic'],
    protectionYears: 5,
    usage: 'at_rest',
    frequency: 'medium',
    examples: ['internal IDs', 'configuration secrets', 'API responses'],
  },
};

// Context config defaults for custom contexts
const CONTEXT_DEFAULTS = {
  sensitivity: 'medium',
  compliance: [],
  adversaries: ['opportunistic'],
  protectionYears: 5,
  usage: 'at_rest',
  frequency: 'medium',
};

// =============================================================================
// Custom context loader
// =============================================================================

/**
 * Load custom contexts from .cryptoserve.json in the given directory.
 * Returns merged built-in + custom contexts.
 */
export function loadContexts(dir = process.cwd()) {
  const contexts = { ...BUILT_IN_CONTEXTS };

  try {
    const configPath = resolve(dir, '.cryptoserve.json');
    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    if (config.contexts && typeof config.contexts === 'object') {
      for (const [name, userCtx] of Object.entries(config.contexts)) {
        // Validate name format
        if (!/^[a-z][a-z0-9-]*$/.test(name)) continue;
        // Merge with defaults
        contexts[name] = { ...CONTEXT_DEFAULTS, ...userCtx, _custom: true };
      }
    }
  } catch { /* no config file or parse error — use built-ins only */ }

  return contexts;
}

// =============================================================================
// 5-Layer Algorithm Resolver
// =============================================================================

/**
 * Resolve a context name to an optimal algorithm and rationale.
 *
 * @param {string} contextName - Context label (e.g. "user-pii")
 * @param {string} [dir] - Directory to look for .cryptoserve.json
 * @returns {{ algorithm, keyBits, context, factors[], alternatives[] }}
 */
export function resolveContext(contextName, dir = process.cwd()) {
  const contexts = loadContexts(dir);
  const ctx = contexts[contextName];
  if (!ctx) {
    return { error: `Unknown context: "${contextName}"`, validContexts: Object.keys(contexts) };
  }

  const factors = [];
  const alternatives = [];

  // ---- Layer 1: Data Identity (Sensitivity) ----
  const sensitivity = ctx.sensitivity || 'medium';
  let minBits = SENSITIVITY_MIN_BITS[sensitivity] || 128;
  factors.push(`Sensitivity: ${sensitivity.toUpperCase()} → ${minBits}-bit minimum`);

  // ---- Layer 2: Regulatory Mapping (Compliance) ----
  let rotationDays = SENSITIVITY_ROTATION[sensitivity] || 180;
  const compliance = ctx.compliance || [];
  for (const framework of compliance) {
    const constraint = COMPLIANCE_CONSTRAINTS[framework];
    if (constraint) {
      minBits = Math.max(minBits, constraint.minBits);
      rotationDays = Math.min(rotationDays, constraint.maxRotationDays);
      factors.push(`Compliance: ${framework} → ${constraint.minBits}-bit min, ${constraint.maxRotationDays}-day rotation`);
    }
  }

  // ---- Layer 3: Threat Model ----
  const adversaries = ctx.adversaries || ['opportunistic'];
  const protectionYears = ctx.protectionYears ?? 5;

  if (adversaries.includes('nation_state')) {
    minBits = Math.max(minBits, 256);
    factors.push('Threat: Nation-state adversary → 256-bit enforced');
  }

  let quantumRisk = false;
  if (adversaries.includes('quantum') || protectionYears > 10) {
    quantumRisk = true;
    minBits = Math.max(minBits, 256);
    const reason = adversaries.includes('quantum')
      ? 'Quantum adversary specified'
      : `Protection period ${protectionYears}yr exceeds quantum horizon`;
    factors.push(`Quantum: ${reason} → 256-bit, PQC recommended`);
  }

  // ---- Layer 4: Access Patterns ----
  const usage = ctx.usage || 'at_rest';
  const frequency = ctx.frequency || 'medium';
  let preferHwAccel = false;

  if (frequency === 'high') {
    preferHwAccel = true;
    factors.push('Access: High frequency → hardware acceleration preferred (AES-NI)');
  }

  if (usage === 'streaming') {
    factors.push('Usage: Streaming → stream cipher preferred');
  }

  // ---- Layer 5: Algorithm Selection ----
  let algorithm;

  if (usage === 'streaming' && minBits <= 256) {
    // Streaming contexts prefer ChaCha20 (native stream cipher)
    algorithm = 'ChaCha20-Poly1305';
    factors.push('Selected: ChaCha20-Poly1305 (native stream cipher for streaming context)');
    alternatives.push({ algorithm: 'AES-256-GCM', reason: 'If AES-NI hardware acceleration is available' });
  } else if (minBits > 128) {
    // 256-bit requirement
    if (preferHwAccel) {
      algorithm = 'AES-256-GCM';
      factors.push('Selected: AES-256-GCM (256-bit, hardware accelerated, FIPS 197 + SP 800-38D)');
      alternatives.push({ algorithm: 'ChaCha20-Poly1305', reason: 'Better on systems without AES-NI' });
    } else {
      // No strong hw-accel preference — still default to AES-256-GCM (most compatible)
      algorithm = 'AES-256-GCM';
      factors.push('Selected: AES-256-GCM (256-bit, widely supported, FIPS compliant)');
      alternatives.push({ algorithm: 'ChaCha20-Poly1305', reason: 'Equal security, better without AES-NI' });
    }
  } else {
    // 128-bit sufficient
    if (preferHwAccel) {
      algorithm = 'AES-128-GCM';
      factors.push('Selected: AES-128-GCM (128-bit sufficient, fast with AES-NI)');
      alternatives.push({ algorithm: 'AES-256-GCM', reason: 'If future-proofing or compliance requires 256-bit' });
      alternatives.push({ algorithm: 'ChaCha20-Poly1305', reason: 'Better on systems without AES-NI' });
    } else {
      algorithm = 'AES-128-GCM';
      factors.push('Selected: AES-128-GCM (128-bit sufficient for threat model)');
      alternatives.push({ algorithm: 'ChaCha20-Poly1305', reason: 'Better performance without AES-NI' });
      alternatives.push({ algorithm: 'AES-256-GCM', reason: 'If upgrading to 256-bit for future-proofing' });
    }
  }

  if (quantumRisk) {
    factors.push('Note: Post-quantum migration recommended — use CryptoServe server for hybrid PQC');
  }

  return {
    algorithm,
    keyBits: EXECUTABLE_ALGORITHMS[algorithm].keyBits,
    context: {
      name: contextName,
      displayName: ctx.displayName || contextName,
      description: ctx.description || '',
      sensitivity,
      compliance,
      adversaries,
      protectionYears,
      usage,
      frequency,
      pii: ctx.pii || false,
      phi: ctx.phi || false,
      pci: ctx.pci || false,
      examples: ctx.examples || [],
      custom: !!ctx._custom,
    },
    rotationDays,
    quantumRisk,
    factors,
    alternatives,
  };
}

/**
 * List all available contexts (built-in + custom).
 *
 * @param {string} [dir] - Directory to look for .cryptoserve.json
 * @returns {Array<{ name, displayName, sensitivity, algorithm, compliance, custom }>}
 */
export function listContexts(dir = process.cwd()) {
  const contexts = loadContexts(dir);
  const result = [];

  for (const [name, ctx] of Object.entries(contexts)) {
    const resolved = resolveContext(name, dir);
    result.push({
      name,
      displayName: ctx.displayName || name,
      description: ctx.description || '',
      sensitivity: ctx.sensitivity || 'medium',
      algorithm: resolved.algorithm,
      compliance: ctx.compliance || [],
      custom: !!ctx._custom,
    });
  }

  return result;
}

// Re-export for CLI validation
export { BUILT_IN_CONTEXTS, EXECUTABLE_ALGORITHMS };
