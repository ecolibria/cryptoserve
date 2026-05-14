const { ml_kem768 } = require('@noble/post-quantum/ml-kem');
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa');

function newKem() {
  return ml_kem768.keygen();
}

function newSigner() {
  return ml_dsa65.keygen();
}

const ALGORITHMS = ['ML-KEM-768', 'ML-DSA-65'];

module.exports = { newKem, newSigner, ALGORITHMS };
