import { CustomError, logger } from '@auth-guide/shared';
import User from '../models/User.js';
import Nonce from '../models/Nonce.js';
import { buildSIWEMessage, verifySIWESignature, lookupENS } from '../utils/ethereum.js';
import { buildSolanaMessage, verifySolanaSignature, isValidSolanaAddress } from '../utils/solana.js';
import { buildBitcoinMessage, verifyBitcoinSignature, isValidBitcoinAddress } from '../utils/bitcoin.js';
import { createTokenPair, sendTokenResponse, formatUser } from '../utils/token.js';

const NONCE_TTL = parseInt(process.env.NONCE_TTL || '10', 10);

const messageBuilders = {
  ethereum: buildSIWEMessage,
  solana: buildSolanaMessage,
  bitcoin: buildBitcoinMessage,
};

const validateAddress = (chain, address) => {
  if (chain === 'ethereum') {
    return /^0x[a-fA-F0-9]{40}$/.test(address);
  }
  if (chain === 'solana') {
    return isValidSolanaAddress(address);
  }
  if (chain === 'bitcoin') {
    return isValidBitcoinAddress(address);
  }
  return false;
};

/**
 * POST /api/web3/nonce
 *
 * Generate a nonce for wallet authentication.
 * Returns nonce + pre-built message to sign.
 *
 * Body: { chain: 'ethereum' | 'solana' | 'bitcoin', address: '0x...' }
 */
const getNonce = async (req, res) => {
  const { chain, address } = req.body;

  if (!chain || !address) {
    throw new CustomError('chain and address are required', 400, true, 'VALIDATION_ERROR');
  }

  if (!['ethereum', 'solana', 'bitcoin'].includes(chain)) {
    throw new CustomError('chain must be ethereum, solana, or bitcoin', 400, true, 'INVALID_CHAIN');
  }

  if (!validateAddress(chain, address)) {
    throw new CustomError(`Invalid ${chain} address format`, 400, true, 'INVALID_ADDRESS');
  }

  // Generate and store nonce
  const nonceDoc = await Nonce.createNonce(chain, address, NONCE_TTL);

  // Build message to sign
  const domain = req.get('host') || 'localhost';
  const uri = `${req.protocol}://${domain}`;

  const buildMessage = messageBuilders[chain];
  const message = buildMessage({
    address,
    nonce: nonceDoc.nonce,
    domain,
    uri,
  });

  res.json({
    success: true,
    data: {
      nonce: nonceDoc.nonce,
      message,
      chain,
      expiresAt: nonceDoc.expiresAt,
    },
  });
};

/**
 *
 * Verify wallet signature and authenticate.
 * Body: { chain, address, message, signature }
 */
const verify = async (req, res) => {
  const { chain, address, message, signature } = req.body;

  if (!chain || !address || !message || !signature) {
    throw new CustomError('chain, address, message, and signature are required', 400, true, 'VALIDATION_ERROR');
  }

  // Extract nonce from message
  const nonceMatch = message.match(/Nonce:\s*([a-f0-9]+)/i);
  if (!nonceMatch) {
    throw new CustomError('No nonce found in message', 400, true, 'NO_NONCE');
  }
  const nonce = nonceMatch[1];

  // Consume nonce (one-time use)
  const nonceDoc = await Nonce.consumeNonce(nonce, chain, address);
  if (!nonceDoc) {
    throw new CustomError('Invalid, expired, or already used nonce', 401, true, 'INVALID_NONCE');
  }

  // Verify signature based on chain
  let verifiedAddress;

  if (chain === 'ethereum') {
    const domain = req.get('host') || 'localhost';
    const result = await verifySIWESignature(message, signature, nonce, domain);
    verifiedAddress = result.address;
  } else if (chain === 'solana') {
    const result = verifySolanaSignature(message, signature, address);
    if (!result.valid) {
      throw new CustomError('Invalid Solana signature', 401, true, 'SOL_VERIFY_FAILED');
    }
    verifiedAddress = result.address;
  } else if (chain === 'bitcoin') {
    const result = await verifyBitcoinSignature(message, address, signature);
    if (!result.valid) {
      throw new CustomError('Invalid Bitcoin signature', 401, true, 'BTC_VERIFY_FAILED');
    }
    verifiedAddress = result.address;
  }

  // Resolve ENS name for Ethereum (optional)
  let displayName = null;
  if (chain === 'ethereum') {
    displayName = await lookupENS(verifiedAddress);
  }

  // Find or create user
  const { user, isNewUser } = await User.findOrCreateByWallet(chain, verifiedAddress, displayName);

  logger.info({
    msg: 'Web3 authentication successful',
    chain,
    address: verifiedAddress,
    userId: user._id,
    isNewUser,
  });

  // Issue JWT session
  const tokens = await createTokenPair({ userId: user._id.toString(), username: user.username, req });

  sendTokenResponse(res, {
    statusCode: 200,
    ...tokens,
    data: { user: formatUser(user), isNewUser, chain },
  });
};

/**
 * POST /api/web3/link
 *
 * Link an additional wallet to existing account.
 * Requires authentication + wallet signature.
 *
 * Body: { chain, address, message, signature }
 */
const linkWallet = async (req, res) => {
  const { chain, address, message, signature } = req.body;

  if (!chain || !address || !message || !signature) {
    throw new CustomError('chain, address, message, and signature are required', 400, true, 'VALIDATION_ERROR');
  }

  // Verify signature first
  const nonceMatch = message.match(/Nonce:\s*([a-f0-9]+)/i);
  if (!nonceMatch) throw new CustomError('No nonce in message', 400, true, 'NO_NONCE');

  const nonceDoc = await Nonce.consumeNonce(nonceMatch[1], chain, address);
  if (!nonceDoc) throw new CustomError('Invalid nonce', 401, true, 'INVALID_NONCE');

  let verifiedAddress;

  if (chain === 'ethereum') {
    const domain = req.get('host') || 'localhost';
    const result = await verifySIWESignature(message, signature, nonceMatch[1], domain);
    verifiedAddress = result.address;
  } else if (chain === 'solana') {
    const result = verifySolanaSignature(message, signature, address);
    if (!result.valid) throw new CustomError('Invalid signature', 401, true, 'VERIFY_FAILED');
    verifiedAddress = result.address;
  } else if (chain === 'bitcoin') {
    const result = await verifyBitcoinSignature(message, address, signature);
    if (!result.valid) throw new CustomError('Invalid signature', 401, true, 'VERIFY_FAILED');
    verifiedAddress = result.address;
  } else {
    throw new CustomError('Unsupported chain', 400, true, 'INVALID_CHAIN');
  }

  // Check if wallet is already linked to another user
  const normalizedAddress = chain === 'ethereum' ? verifiedAddress.toLowerCase() : verifiedAddress;
  const existingUser = await User.findByWallet(chain, normalizedAddress);
  if (existingUser && existingUser._id.toString() !== req.userId) {
    throw new CustomError('This wallet is already linked to another account', 409, true, 'WALLET_CONFLICT');
  }

  // Link wallet
  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const alreadyLinked = user.wallets.find(w => w.chain === chain && w.address === normalizedAddress);
  if (alreadyLinked) {
    throw new CustomError('Wallet already linked to your account', 400, true, 'ALREADY_LINKED');
  }

  let displayName = null;
  if (chain === 'ethereum') displayName = await lookupENS(verifiedAddress);

  user.wallets.push({
    chain,
    address: normalizedAddress,
    displayName,
    linkedAt: new Date(),
    lastUsedAt: new Date(),
  });

  await user.save();

  logger.info({ msg: 'Wallet linked', userId: user._id, chain, address: normalizedAddress });

  res.json({
    success: true,
    data: { user: formatUser(user), linkedWallet: { chain, address: normalizedAddress } },
  });
};

/**
 * List user's linked wallets
 */
const getWallets = async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  res.json({
    success: true,
    data: {
      wallets: user.wallets.map(w => ({
        id: w._id,
        chain: w.chain,
        address: w.address,
        displayName: w.displayName,
        linkedAt: w.linkedAt,
        lastUsedAt: w.lastUsedAt,
      })),
      primaryWallet: user.primaryWallet,
    },
  });
};

/**
 * Unlink a wallet (must keep at least one)
 */
const unlinkWallet = async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  if (user.wallets.length <= 1) {
    throw new CustomError('Cannot unlink last wallet — account requires at least one', 400, true, 'LAST_WALLET');
  }

  const walletIndex = user.wallets.findIndex(w => w._id.toString() === req.params.id);
  if (walletIndex === -1) throw new CustomError('Wallet not found', 404, true, 'WALLET_NOT_FOUND');

  const removed = user.wallets.splice(walletIndex, 1)[0];

  // If primary wallet was removed, set first remaining as primary
  if (user.primaryWallet.address === removed.address) {
    user.primaryWallet = {
      chain: user.wallets[0].chain,
      address: user.wallets[0].address,
    };
  }

  await user.save();

  res.json({ success: true, data: { message: 'Wallet unlinked', user: formatUser(user) } });
};

export { getNonce, verify, linkWallet, getWallets, unlinkWallet };
