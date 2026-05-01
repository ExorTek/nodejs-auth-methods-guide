import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { CustomError } from '@auth-guide/shared';

/**
 * Solana Authentication Utils
 *
 * Solana uses Ed25519 signatures (same as WebAuthn can use).
 * Wallets like Phantom and Solflare support signMessage().
 *
 * Flow (similar to SIWE but Solana-native):
 *   1. Server builds human-readable message with nonce
 *   2. User signs with Phantom/Solflare (signMessage)
 *   3. Server verifies Ed25519 signature with public key (wallet address)
 *   4. Address matches → authenticated
 *
 * No standard like SIWE yet for Solana, but "Sign-In with Solana" (SIWS)
 * proposals exist. We use a structured message format.
 */

/**
 * Build Solana sign-in message
 *
 * @param {Object} params
 * @param {string} params.address - Solana public key (base58)
 * @param {string} params.nonce - Server-generated nonce
 * @param {string} params.domain - App domain
 * @param {string} params.statement - Human-readable statement
 * @returns {string} Message to sign
 */
const buildSolanaMessage = ({ address, nonce, domain, statement }) => {
  const issuedAt = new Date().toISOString();

  return [
    `${domain} wants you to sign in with your Solana account:`,
    address,
    '',
    statement || 'Sign in to AuthGuide with your Solana wallet.',
    '',
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join('\n');
};

/**
 * Verify Solana signature (Ed25519)
 *
 * @param {string} message - Original message that was signed
 * @param {string} signatureB58 - Base58-encoded signature from wallet
 * @param {string} publicKeyB58 - Solana public key (base58 address)
 * @returns {{ valid: boolean, address: string }}
 */
const verifySolanaSignature = (message, signatureB58, publicKeyB58) => {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const signatureBytes = bs58.decode(signatureB58);
    const publicKeyBytes = bs58.decode(publicKeyB58);

    const isValid = nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);

    return {
      valid: isValid,
      address: publicKeyB58,
    };
  } catch (err) {
    throw new CustomError(`Solana signature verification failed: ${err.message}`, 401, true, 'SOL_VERIFY_FAILED');
  }
};

/**
 * Validate Solana address format (base58, 32-44 chars)
 */
const isValidSolanaAddress = address => {
  try {
    const decoded = bs58.decode(address);
    return decoded.length === 32;
  } catch {
    return false;
  }
};

export { buildSolanaMessage, verifySolanaSignature, isValidSolanaAddress };
