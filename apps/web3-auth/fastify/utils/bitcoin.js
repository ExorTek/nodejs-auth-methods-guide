import { CustomError } from '@auth-guide/shared';

/**
 * Bitcoin Authentication Utils
 *
 * Bitcoin message signing uses the BIP-137 standard.
 * Wallets like Xverse, Unisat, and Leather support signMessage().
 *
 * Bitcoin addresses come in multiple formats:
 *   - Legacy (1...): P2PKH — original format
 *   - SegWit (3...): P2SH-P2WPKH — wrapped segwit
 *   - Native SegWit (bc1q...): P2WPKH — bech32
 *   - Taproot (bc1p...): P2TR — bech32m, used by Ordinals
 *
 * Flow:
 *   1. Server builds message with nonce
 *   2. User signs with Bitcoin wallet (signMessage)
 *   3. Server verifies signature against address
 *   4. Address matches → authenticated
 */

/**
 * Build Bitcoin sign-in message
 *
 * @param {Object} params
 * @param {string} params.address - Bitcoin address
 * @param {string} params.nonce - Server-generated nonce
 * @param {string} params.domain - App domain
 * @param {string} params.statement - Human-readable statement
 * @returns {string} Message to sign
 */
const buildBitcoinMessage = ({ address, nonce, domain, statement }) => {
  const issuedAt = new Date().toISOString();

  return [
    `${domain} wants you to sign in with your Bitcoin account:`,
    address,
    '',
    statement || 'Sign in to AuthGuide with your Bitcoin wallet.',
    '',
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join('\n');
};

/**
 * Verify Bitcoin message signature
 *
 * Uses bitcoinjs-message library for BIP-137 verification.
 * Handles Legacy, SegWit, and Native SegWit addresses.
 *
 * @param {string} message - Original message
 * @param {string} address - Bitcoin address
 * @param {string} signature - Base64-encoded signature
 * @returns {{ valid: boolean, address: string }}
 */
const verifyBitcoinSignature = async (message, address, signature) => {
  try {
    // Dynamic import — bitcoinjs-message is CJS
    const bitcoinMessage = await import('bitcoinjs-message');
    const verify = bitcoinMessage.default?.verify || bitcoinMessage.verify;

    // bitcoinjs-message.verify(message, address, signature, null, true)
    // Last param `true` enables segwit address support
    const isValid = verify(message, address, signature, null, true);

    return { valid: isValid, address };
  } catch (err) {
    // Some Taproot (bc1p) addresses may not be supported by bitcoinjs-message
    // In that case, we need alternative verification
    if (address.startsWith('bc1p')) {
      throw new CustomError(
        'Taproot (bc1p) address verification requires additional libraries. Use a Legacy or SegWit address for now.',
        400,
        true,
        'BTC_TAPROOT_UNSUPPORTED',
      );
    }

    throw new CustomError(`Bitcoin signature verification failed: ${err.message}`, 401, true, 'BTC_VERIFY_FAILED');
  }
};

/**
 * Validate Bitcoin address format (basic check)
 */
const isValidBitcoinAddress = address => {
  if (!address || address.length < 26 || address.length > 62) return false;

  // Legacy
  if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(address)) return true;
  // Native SegWit (bech32)
  if (/^bc1q[a-z0-9]{38,}$/.test(address)) return true;
  // Taproot (bech32m)
  if (/^bc1p[a-z0-9]{58}$/.test(address)) return true;

  return false;
};

export { buildBitcoinMessage, verifyBitcoinSignature, isValidBitcoinAddress };
