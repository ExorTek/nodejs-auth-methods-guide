import { ethers } from 'ethers';
import { SiweMessage } from 'siwe';
import { CustomError } from '@auth-guide/shared';

/**
 * Ethereum Authentication Utils
 *
 * Uses SIWE (Sign-In with Ethereum) — EIP-4361
 * Standard message format that wallets display to users,
 * preventing blind signing attacks.
 *
 * Flow:
 *   1. Server builds SIWE message with nonce, domain, URI
 *   2. User signs message with MetaMask/WalletConnect
 *   3. Server verifies signature recovers address
 *   4. Address matches → authenticated
 */

/**
 * Build SIWE message string
 *
 * @param {Object} params
 * @param {string} params.address - Ethereum address (0x...)
 * @param {string} params.nonce - Server-generated nonce
 * @param {string} params.domain - App domain (e.g. localhost)
 * @param {string} params.uri - App URI (e.g. http://localhost:3010)
 * @param {string} params.statement - Human-readable statement
 * @param {string} params.chainId - Ethereum chain ID (1 = mainnet, 5 = goerli)
 */
const buildSIWEMessage = ({ address, nonce, domain, uri, statement, chainId = '1' }) => {
  const message = new SiweMessage({
    domain,
    address: ethers.getAddress(address),
    statement: statement || 'Sign in to AuthGuide with your Ethereum wallet.',
    uri,
    version: '1',
    chainId: parseInt(chainId, 10),
    nonce,
    issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
  });

  return message.prepareMessage();
};

/**
 * Verify SIWE signature
 *
 * Parses the SIWE message, verifies the signature,
 * and checks nonce, domain, expiration.
 *
 * @param {string} message - SIWE message string
 * @param {string} signature - Hex signature from wallet
 * @param {string} expectedNonce - Server-stored nonce
 * @param {string} expectedDomain - Expected domain
 * @returns {Promise<{ address: string, chainId: number }>}
 */
const verifySIWESignature = async (message, signature, expectedNonce, expectedDomain) => {
  try {
    const siweMessage = new SiweMessage(message);

    const { data: fields } = await siweMessage.verify({
      signature,
      nonce: expectedNonce,
      domain: expectedDomain,
    });

    return {
      address: fields.address.toLowerCase(),
      chainId: fields.chainId,
    };
  } catch (err) {
    throw new CustomError(`Ethereum signature verification failed: ${err.message}`, 401, true, 'ETH_VERIFY_FAILED');
  }
};

/**
 * Verify raw Ethereum signature (non-SIWE — simple message signing)
 * Used as fallback or for simpler integrations
 *
 * @param {string} message - Plain text message
 * @param {string} signature - Hex signature
 * @param {string} expectedAddress - Expected signer address
 * @returns {boolean}
 */
const verifyEthSignature = (message, signature, expectedAddress) => {
  try {
    const recoveredAddress = ethers.verifyMessage(message, signature);
    return recoveredAddress.toLowerCase() === expectedAddress.toLowerCase();
  } catch {
    return false;
  }
};

/**
 * Resolve ENS name to address (optional — requires RPC)
 */
const resolveENS = async ensName => {
  const rpcUrl = process.env.ETH_RPC_URL;
  if (!rpcUrl) return null;

  try {
    const provider = new ethers.JsonRpcProvider(rpcUrl);
    return await provider.resolveName(ensName);
  } catch {
    return null;
  }
};

/**
 * Reverse-resolve address to ENS name (optional)
 */
const lookupENS = async address => {
  const rpcUrl = process.env.ETH_RPC_URL;
  if (!rpcUrl) return null;

  try {
    const provider = new ethers.JsonRpcProvider(rpcUrl);
    return await provider.lookupAddress(address);
  } catch {
    return null;
  }
};

export { buildSIWEMessage, verifySIWESignature, verifyEthSignature, resolveENS, lookupENS };
