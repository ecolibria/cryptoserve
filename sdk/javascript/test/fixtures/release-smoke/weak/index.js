const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

// AWS' own documented example access key. Pattern is recognized by
// CryptoServe's scanner; value is universally treated as a placeholder
// (matches GitHub's well-known-example list, so push protection allows it).
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';

function fingerprint(value) {
  return crypto.createHash('md5').update(value).digest('hex');
}

function issue(claims) {
  return jwt.sign(claims, 'shared-secret', { algorithm: 'RS256' });
}

const legacyCipher = crypto.createCipheriv('des-cbc', Buffer.alloc(8), Buffer.alloc(8));

module.exports = { fingerprint, issue, legacyCipher, AWS_ACCESS_KEY_ID };
