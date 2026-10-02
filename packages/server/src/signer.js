import { spawn } from 'node:child_process';
import {
  generateIdentity,
  identityFromPem,
  identityFromPublicKey,
  sign as signLocally,
  verify,
} from '@deedwrit/core';
import { newId, now } from './db.js';

/**
 * Where the hub's private keys live.
 *
 * Until now they lived in the hub's own database, which meant anyone who
 * obtained that file could sign checkpoints as the hub. That never let them
 * forge a *receipt* — agents hold those keys and the hub never sees them — but
 * it did let them attest to a history the hub never held, and "the witnesses
 * would catch it" is defence in depth, not key management.
 *
 * A signer is deliberately the smallest possible interface:
 *
 *     { kid, publicKey, async sign(digest) -> base64url }
 *
 * That is all the receipt format ever needs, which is why a KMS, an HSM, or a
 * Vault transit engine is an adapter here rather than a redesign. Everything
 * below is an implementation of those three members.
 *
 * Signing is async throughout, because the useful implementations are.
 */

/**
 * @typedef {object} Signer
 * @property {string} kid
 * @property {string} publicKey             Raw Ed25519 public key, base64url.
 * @property {string} kind                  For diagnostics and the console.
 * @property {(digest: Buffer) => Promise<string>} sign
 */

/**
 * The key material sits in this process. Correct for development and for a
 * single-tenant self-hosted hub whose operator accepts the risk knowingly;
 * not what a hosted service should run.
 *
 * @param {string} privateKeyPem
 * @returns {Signer}
 */
export function localSigner(privateKeyPem) {
  const identity = identityFromPem(privateKeyPem);
  return {
    kid: identity.kid,
    publicKey: identity.publicKey,
    kind: 'local',
    async sign(digest) {
      return signLocally(identity, digest);
    },
  };
}

/**
 * Signing happens in another process: a KMS wrapper script, a PKCS#11 tool, a
 * `vault write` call. The digest arrives on stdin as raw bytes and the
 * signature is expected on stdout as base64url, base64 or hex.
 *
 * This is the adapter that covers every key store at once, because every key
 * store has a command-line client. It costs one process spawn per checkpoint —
 * which happens once per few hundred receipts, not per receipt.
 *
 * @param {object} opts
 * @param {string} opts.command
 * @param {string[]} [opts.args]
 * @param {string} opts.publicKey  Raw Ed25519 public key, base64url.
 * @param {number} [opts.timeoutMs]
 * @returns {Signer}
 */
export function commandSigner(opts) {
  const identity = identityFromPublicKey(opts.publicKey);
  const timeoutMs = opts.timeoutMs ?? 15_000;

  return {
    kid: identity.kid,
    publicKey: identity.publicKey,
    kind: 'command',
    sign(digest) {
      return new Promise((resolve, reject) => {
        const child = spawn(opts.command, opts.args ?? [], {
          stdio: ['pipe', 'pipe', 'pipe'],
        });

        let out = '';
        let err = '';
        const timer = setTimeout(() => {
          child.kill('SIGKILL');
          reject(new Error(`signer command timed out after ${timeoutMs}ms`));
        }, timeoutMs);

        child.stdout.on('data', (c) => (out += c));
        child.stderr.on('data', (c) => (err += c));
        child.on('error', (e) => {
          clearTimeout(timer);
          reject(new Error(`could not run signer command: ${e.message}`));
        });
        child.on('close', (code) => {
          clearTimeout(timer);
          if (code !== 0) {
            reject(new Error(`signer command exited ${code}: ${err.trim().slice(0, 200)}`));
            return;
          }
          try {
            resolve(normalizeSignature(out.trim()));
          } catch (e) {
            reject(e);
          }
        });

        child.stdin.end(digest);
      });
    },
  };
}

/**
 * Signing happens over HTTP — a sidecar holding a KMS client, or a signing
 * service shared across hubs.
 *
 * @param {object} opts
 * @param {string} opts.url
 * @param {string} opts.publicKey
 * @param {Record<string,string>} [opts.headers]
 * @param {number} [opts.timeoutMs]
 * @returns {Signer}
 */
export function httpSigner(opts) {
  const identity = identityFromPublicKey(opts.publicKey);
  const timeoutMs = opts.timeoutMs ?? 15_000;

  return {
    kid: identity.kid,
    publicKey: identity.publicKey,
    kind: 'http',
    async sign(digest) {
      const res = await fetch(opts.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(opts.headers ?? {}) },
        body: JSON.stringify({ kid: identity.kid, digest: digest.toString('base64url') }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) {
        throw new Error(`signing service returned HTTP ${res.status}`);
      }
      const body = await res.json();
      if (typeof body?.signature !== 'string') {
        throw new Error('signing service did not return a "signature" field');
      }
      return normalizeSignature(body.signature);
    },
  };
}

/**
 * Accept whichever encoding the key store happens to emit, and normalise to
 * the base64url the wire format uses. An Ed25519 signature is always 64 bytes,
 * which is enough to tell the encodings apart unambiguously.
 *
 * @param {string} text
 * @returns {string}
 */
export function normalizeSignature(text) {
  const trimmed = text.trim();
  if (trimmed === '') throw new Error('signer returned an empty signature');

  /** @type {Buffer} */
  let bytes;
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
    bytes = Buffer.from(trimmed, 'hex');
  } else {
    // base64 and base64url both round-trip through base64url decoding once
    // the two substituted characters are mapped back.
    bytes = Buffer.from(
      trimmed.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
      'base64url',
    );
  }

  if (bytes.length !== 64) {
    // Report the real length: an operator wiring up a KMS needs to know
    // whether they got a 32-byte digest back, a DER-wrapped blob, or an
    // error page, and "? bytes" tells them none of that.
    throw new Error(
      `signer returned ${bytes.length} bytes; an Ed25519 signature is 64. ` +
        `Got: ${JSON.stringify(trimmed.slice(0, 48))}`,
    );
  }
  return bytes.toString('base64url');
}

/**
 * A signer that refuses to sign.
 *
 * Configuring an external signer whose public key is unknown is a
 * misconfiguration, and the safe response is to stop signing rather than to
 * fall back to a local key nobody asked for. Checkpoints stop; ingest, the
 * part that actually protects customers, keeps working.
 *
 * @param {string} reason
 * @returns {Signer}
 */
export function disabledSigner(reason) {
  return {
    kid: 'pw1disabled',
    publicKey: '',
    kind: 'disabled',
    async sign() {
      throw new Error(`signing is disabled: ${reason}`);
    },
  };
}

/**
 * Wrap a signer so a bad configuration is caught at startup rather than the
 * first time a checkpoint is due.
 *
 * The check is a real signature over a random digest, verified against the
 * configured public key. That catches every interesting failure at once: the
 * command not existing, the KMS denying access, the wrong key being wired up,
 * and an output encoding nobody thought about.
 *
 * @param {Signer} signer
 * @returns {Promise<{ ok: boolean, error?: string }>}
 */
export async function selfTest(signer) {
  if (signer.kind === 'disabled') return { ok: false, error: 'signing is disabled' };
  try {
    const { randomBytes } = await import('node:crypto');
    const digest = randomBytes(32);
    const sig = await signer.sign(digest);
    if (!verify(signer.publicKey, digest, sig)) {
      return {
        ok: false,
        error:
          'the signer produced a signature that does not verify against its configured ' +
          'public key — the key and the signer do not match',
      };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: /** @type {Error} */ (err).message };
  }
}

/**
 * Build the hub's signers from configuration.
 *
 * `DEEDWRIT_SIGNER` selects the backend for both roles; each role may also be
 * configured separately, because a deployment might put the witness key in a
 * different custody than the log key — which is exactly what an independent
 * witness *should* do.
 *
 * @param {import('./store.js').Store} store
 * @param {'hub'|'witness'} role
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {Signer}
 */
export function signerFor(store, role, env = process.env) {
  const upper = role.toUpperCase();
  const kind = env[`DEEDWRIT_${upper}_SIGNER`] ?? env.DEEDWRIT_SIGNER ?? 'local';
  const publicKey = env[`DEEDWRIT_${upper}_PUBLIC_KEY`] ?? env.DEEDWRIT_PUBLIC_KEY;

  switch (kind) {
    case 'local': {
      // Only the local backend ever writes key material, and only it can
      // create a key on demand.
      const row = store.activeServerKey(role);
      if (row) return localSigner(row.private_pem);
      const { identity, privateKeyPem } = generateIdentity();
      store.recordServerKey({
        kid: identity.kid,
        role,
        publicKey: identity.publicKey,
        privatePem: privateKeyPem,
      });
      return localSigner(privateKeyPem);
    }

    case 'command': {
      const command = env[`DEEDWRIT_${upper}_SIGNER_COMMAND`] ?? env.DEEDWRIT_SIGNER_COMMAND;
      if (!command || !publicKey) {
        return disabledSigner(
          `signer "command" needs DEEDWRIT_${upper}_SIGNER_COMMAND (or DEEDWRIT_SIGNER_COMMAND) ` +
            `and DEEDWRIT_${upper}_PUBLIC_KEY`,
        );
      }
      const args = (env[`DEEDWRIT_${upper}_SIGNER_ARGS`] ?? env.DEEDWRIT_SIGNER_ARGS ?? '')
        .split(' ')
        .filter(Boolean);
      const signer = commandSigner({ command, args, publicKey });
      // Record the public half so verifiers and bundles can find it. The
      // private half is, by construction, not ours to store.
      store.recordServerKey({ kid: signer.kid, role, publicKey: signer.publicKey, privatePem: null });
      return signer;
    }

    case 'http': {
      const url = env[`DEEDWRIT_${upper}_SIGNER_URL`] ?? env.DEEDWRIT_SIGNER_URL;
      if (!url || !publicKey) {
        return disabledSigner(
          `signer "http" needs DEEDWRIT_${upper}_SIGNER_URL (or DEEDWRIT_SIGNER_URL) ` +
            `and DEEDWRIT_${upper}_PUBLIC_KEY`,
        );
      }
      const token = env[`DEEDWRIT_${upper}_SIGNER_TOKEN`] ?? env.DEEDWRIT_SIGNER_TOKEN;
      const signer = httpSigner({
        url,
        publicKey,
        headers: token ? { authorization: `Bearer ${token}` } : undefined,
      });
      store.recordServerKey({ kid: signer.kid, role, publicKey: signer.publicKey, privatePem: null });
      return signer;
    }

    default:
      return disabledSigner(`unknown signer backend "${kind}"`);
  }
}

/**
 * @param {object} args
 * @param {string} args.kid
 * @param {string} args.role
 * @param {string} args.publicKey
 * @returns {object}
 */
export function serverKeyRow(args) {
  return { ...args, created_at: now(), id: newId('key') };
}
