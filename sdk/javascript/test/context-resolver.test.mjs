import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { resolveContext, listContexts, BUILT_IN_CONTEXTS } from '../lib/context-resolver.mjs';

// ---------------------------------------------------------------------------
// Built-in context resolution
// ---------------------------------------------------------------------------

describe('resolveContext (built-in)', () => {
  it('resolves user-pii to AES-256-GCM', () => {
    const r = resolveContext('user-pii');
    assert.equal(r.algorithm, 'AES-256-GCM');
    assert.equal(r.keyBits, 256);
    assert.equal(r.context.sensitivity, 'high');
    assert.ok(r.context.pii);
    assert.ok(r.context.compliance.includes('GDPR'));
  });

  it('resolves payment-data to AES-256-GCM', () => {
    const r = resolveContext('payment-data');
    assert.equal(r.algorithm, 'AES-256-GCM');
    assert.equal(r.keyBits, 256);
    assert.equal(r.context.sensitivity, 'critical');
    assert.ok(r.context.pci);
    assert.ok(r.context.compliance.includes('PCI-DSS'));
  });

  it('resolves session-tokens to AES-128-GCM', () => {
    const r = resolveContext('session-tokens');
    assert.equal(r.algorithm, 'AES-128-GCM');
    assert.equal(r.keyBits, 128);
    assert.equal(r.context.sensitivity, 'medium');
  });

  it('resolves health-data to AES-256-GCM', () => {
    const r = resolveContext('health-data');
    assert.equal(r.algorithm, 'AES-256-GCM');
    assert.equal(r.keyBits, 256);
    assert.equal(r.context.sensitivity, 'critical');
    assert.ok(r.context.phi);
    assert.ok(r.context.compliance.includes('HIPAA'));
    assert.ok(r.quantumRisk); // 25yr protection > 10yr quantum horizon
  });

  it('resolves general to AES-128-GCM', () => {
    const r = resolveContext('general');
    assert.equal(r.algorithm, 'AES-128-GCM');
    assert.equal(r.keyBits, 128);
    assert.equal(r.context.sensitivity, 'medium');
  });

  it('returns error for unknown context', () => {
    const r = resolveContext('nonexistent');
    assert.ok(r.error);
    assert.ok(r.validContexts.length > 0);
  });

  it('includes resolution factors', () => {
    const r = resolveContext('user-pii');
    assert.ok(r.factors.length >= 3); // sensitivity + compliance + threat + selection
  });

  it('includes alternatives', () => {
    const r = resolveContext('user-pii');
    assert.ok(r.alternatives.length > 0);
    assert.ok(r.alternatives[0].algorithm);
    assert.ok(r.alternatives[0].reason);
  });

  it('sets quantum risk for long protection periods', () => {
    const r = resolveContext('health-data'); // 25 years
    assert.ok(r.quantumRisk);
    assert.ok(r.factors.some(f => f.includes('quantum') || f.includes('Quantum')));
  });

  it('sets key rotation based on compliance', () => {
    const pci = resolveContext('payment-data');
    assert.ok(pci.rotationDays <= 90); // PCI-DSS caps at 90

    const general = resolveContext('general');
    assert.ok(general.rotationDays >= 180); // No compliance pressure
  });
});

// ---------------------------------------------------------------------------
// Built-in preset coverage
// ---------------------------------------------------------------------------

describe('built-in presets', () => {
  it('has exactly 5 built-in contexts', () => {
    assert.equal(Object.keys(BUILT_IN_CONTEXTS).length, 5);
  });

  it('all presets have required fields', () => {
    for (const [name, ctx] of Object.entries(BUILT_IN_CONTEXTS)) {
      assert.ok(ctx.displayName, `${name} missing displayName`);
      assert.ok(ctx.description, `${name} missing description`);
      assert.ok(ctx.sensitivity, `${name} missing sensitivity`);
      assert.ok(Array.isArray(ctx.compliance), `${name} missing compliance`);
      assert.ok(Array.isArray(ctx.adversaries), `${name} missing adversaries`);
      assert.ok(typeof ctx.protectionYears === 'number', `${name} missing protectionYears`);
      assert.ok(Array.isArray(ctx.examples), `${name} missing examples`);
    }
  });
});

// ---------------------------------------------------------------------------
// Custom context loading
// ---------------------------------------------------------------------------

describe('custom contexts', () => {
  let tmpDir;

  before(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'ctx-test-'));
    writeFileSync(join(tmpDir, '.cryptoserve.json'), JSON.stringify({
      contexts: {
        'patient-records': {
          displayName: 'Patient Records',
          description: 'Hospital patient data',
          sensitivity: 'critical',
          compliance: ['HIPAA'],
          adversaries: ['organized_crime', 'nation_state'],
          protectionYears: 25,
          usage: 'at_rest',
          frequency: 'medium',
        },
        'chat-logs': {
          sensitivity: 'low',
        },
        'InvalidName': {
          sensitivity: 'medium',
        },
      },
    }));
  });

  after(() => {
    rmSync(tmpDir, { recursive: true });
  });

  it('loads custom context and resolves it', () => {
    const r = resolveContext('patient-records', tmpDir);
    assert.equal(r.algorithm, 'AES-256-GCM');
    assert.equal(r.context.sensitivity, 'critical');
    assert.ok(r.context.custom);
  });

  it('applies defaults to minimal custom context', () => {
    const r = resolveContext('chat-logs', tmpDir);
    assert.equal(r.algorithm, 'AES-128-GCM'); // low sensitivity → 128-bit
    assert.equal(r.context.sensitivity, 'low');
    assert.deepEqual(r.context.adversaries, ['opportunistic']); // default
    assert.ok(r.context.custom);
  });

  it('skips invalid context names', () => {
    const r = resolveContext('InvalidName', tmpDir);
    assert.ok(r.error); // uppercase name rejected
  });

  it('built-in contexts still available alongside custom', () => {
    const r = resolveContext('user-pii', tmpDir);
    assert.equal(r.algorithm, 'AES-256-GCM');
    assert.ok(!r.context.custom);
  });
});

// ---------------------------------------------------------------------------
// listContexts
// ---------------------------------------------------------------------------

describe('listContexts', () => {
  it('lists at least 5 contexts', () => {
    const list = listContexts();
    assert.ok(list.length >= 5);
  });

  it('each entry has required fields', () => {
    const list = listContexts();
    for (const ctx of list) {
      assert.ok(ctx.name);
      assert.ok(ctx.displayName);
      assert.ok(ctx.sensitivity);
      assert.ok(ctx.algorithm);
    }
  });

  it('includes custom contexts when present', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'ctx-list-'));
    writeFileSync(join(tmpDir, '.cryptoserve.json'), JSON.stringify({
      contexts: { 'my-ctx': { sensitivity: 'high' } },
    }));

    const list = listContexts(tmpDir);
    const custom = list.find(c => c.name === 'my-ctx');
    assert.ok(custom);
    assert.ok(custom.custom);

    rmSync(tmpDir, { recursive: true });
  });
});

// ---------------------------------------------------------------------------
// Streaming usage context
// ---------------------------------------------------------------------------

describe('streaming context', () => {
  it('resolves streaming usage to ChaCha20-Poly1305', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'ctx-stream-'));
    writeFileSync(join(tmpDir, '.cryptoserve.json'), JSON.stringify({
      contexts: {
        'live-feed': {
          sensitivity: 'medium',
          usage: 'streaming',
        },
      },
    }));

    const r = resolveContext('live-feed', tmpDir);
    assert.equal(r.algorithm, 'ChaCha20-Poly1305');
    assert.ok(r.factors.some(f => f.includes('stream')));

    rmSync(tmpDir, { recursive: true });
  });
});

// ---------------------------------------------------------------------------
// Nation-state escalation
// ---------------------------------------------------------------------------

describe('threat escalation', () => {
  it('nation-state adversary forces 256-bit', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'ctx-nation-'));
    writeFileSync(join(tmpDir, '.cryptoserve.json'), JSON.stringify({
      contexts: {
        'classified': {
          sensitivity: 'medium', // normally 128-bit
          adversaries: ['nation_state'],
        },
      },
    }));

    const r = resolveContext('classified', tmpDir);
    assert.equal(r.algorithm, 'AES-256-GCM'); // escalated from 128 to 256
    assert.ok(r.factors.some(f => f.includes('Nation-state')));

    rmSync(tmpDir, { recursive: true });
  });
});
