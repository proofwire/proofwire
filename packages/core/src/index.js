/**
 * Proofwire core — tamper-evident receipts for AI agent actions.
 *
 * @see https://github.com/proofwire/proofwire#readme
 */

export { canonicalize, canonicalBytes } from './canonical.js';
export {
  sha256,
  hashObject,
  hex,
  unhex,
  equalBytes,
  LEAF_PREFIX,
  NODE_PREFIX,
  RECEIPT_PREFIX,
  CHECKPOINT_PREFIX,
} from './hash.js';
export {
  generateIdentity,
  identityFromPem,
  identityFromPublicKey,
  publicKeyObject,
  keyIdFor,
  sign,
  verify,
} from './keys.js';
export {
  MerkleTree,
  leafHash,
  nodeHash,
  merkleRoot,
  inclusionProof,
  verifyInclusion,
  consistencyProof,
  verifyConsistency,
} from './merkle.js';
export {
  RECEIPT_VERSION,
  GENESIS_PREV,
  seal,
  openSeal,
  buildReceipt,
  receiptDigest,
  entryHash,
  signReceipt,
  verifyReceipt,
  verifyChain,
} from './receipt.js';
export {
  CHECKPOINT_VERSION,
  buildCheckpoint,
  checkpointDigest,
  signCheckpoint,
  signCheckpointWith,
  cosign,
  cosignWith,
  verifyCheckpoint,
} from './checkpoint.js';
export { ProofLog, verifyBundle, consistencyFor } from './log.js';
export { Policy, History, parseWindow, globMatch } from './policy.js';
export { regexProblem } from './safe-regex.js';
export { redact, hasSecrets, DEFAULT_DETECTORS } from './redact.js';
export { findUnfinished, DEFAULT_GRACE_MS } from './unfinished.js';
export { Recorder, PolicyDenied, NO_POLICY, recordTools } from './recorder.js';
export { POLICY_TEMPLATES, policyTemplate, composePolicy } from './templates.js';
export { witnessCheckpoint, WitnessRefusal } from './witness-client.js';
