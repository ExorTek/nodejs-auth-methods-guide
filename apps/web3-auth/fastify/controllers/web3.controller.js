import { CustomError, logger } from '@auth-guide/shared';
import User from '../models/User.js';
import Nonce from '../models/Nonce.js';
import { buildSIWEMessage, verifySIWESignature, lookupENS } from '../utils/ethereum.js';
import { buildSolanaMessage, verifySolanaSignature, isValidSolanaAddress } from '../utils/solana.js';
import { buildBitcoinMessage, verifyBitcoinSignature, isValidBitcoinAddress } from '../utils/bitcoin.js';
import { createTokenPair, sendTokenResponse, formatUser } from '../utils/token.js';

const NONCE_TTL = parseInt(process.env.NONCE_TTL || '10', 10);

const messageBuilders = { ethereum: buildSIWEMessage, solana: buildSolanaMessage, bitcoin: buildBitcoinMessage };

const validateAddress = (chain, address) => {
  if (chain === 'ethereum') return /^0x[a-fA-F0-9]{40}$/.test(address);
  if (chain === 'solana') return isValidSolanaAddress(address);
  if (chain === 'bitcoin') return isValidBitcoinAddress(address);
  return false;
};

const getNonce = async (request, reply) => {
  const { chain, address } = request.body;
  if (!chain || !address) throw new CustomError('chain and address required', 400, true, 'VALIDATION_ERROR');
  if (!['ethereum', 'solana', 'bitcoin'].includes(chain))
    throw new CustomError('Invalid chain', 400, true, 'INVALID_CHAIN');
  if (!validateAddress(chain, address)) throw new CustomError(`Invalid ${chain} address`, 400, true, 'INVALID_ADDRESS');

  const nonceDoc = await Nonce.createNonce(chain, address, NONCE_TTL);
  const domain = request.hostname || 'localhost';
  const uri = `${request.protocol}://${domain}`;
  const message = messageBuilders[chain]({ address, nonce: nonceDoc.nonce, domain, uri });

  reply
    .code(200)
    .send({ success: true, data: { nonce: nonceDoc.nonce, message, chain, expiresAt: nonceDoc.expiresAt } });
};

const verify = async (request, reply) => {
  const { chain, address, message, signature } = request.body;
  if (!chain || !address || !message || !signature)
    throw new CustomError('chain, address, message, signature required', 400, true, 'VALIDATION_ERROR');

  const nonceMatch = message.match(/Nonce:\s*([a-f0-9]+)/i);
  if (!nonceMatch) throw new CustomError('No nonce in message', 400, true, 'NO_NONCE');

  const nonceDoc = await Nonce.consumeNonce(nonceMatch[1], chain, address);
  if (!nonceDoc) throw new CustomError('Invalid nonce', 401, true, 'INVALID_NONCE');

  let verifiedAddress;

  if (chain === 'ethereum') {
    const domain = request.hostname || 'localhost';
    const result = await verifySIWESignature(message, signature, nonceMatch[1], domain);
    verifiedAddress = result.address;
  } else if (chain === 'solana') {
    const result = verifySolanaSignature(message, signature, address);
    if (!result.valid) throw new CustomError('Invalid Solana signature', 401, true, 'SOL_VERIFY_FAILED');
    verifiedAddress = result.address;
  } else if (chain === 'bitcoin') {
    const result = await verifyBitcoinSignature(message, address, signature);
    if (!result.valid) throw new CustomError('Invalid Bitcoin signature', 401, true, 'BTC_VERIFY_FAILED');
    verifiedAddress = result.address;
  }

  let displayName = null;
  if (chain === 'ethereum') displayName = await lookupENS(verifiedAddress);

  const { user, isNewUser } = await User.findOrCreateByWallet(chain, verifiedAddress, displayName);
  logger.info({ msg: 'Web3 auth successful', chain, address: verifiedAddress, userId: user._id, isNewUser });

  const tokens = await createTokenPair({ userId: user._id.toString(), username: user.username, request });
  sendTokenResponse(reply, { statusCode: 200, ...tokens, data: { user: formatUser(user), isNewUser, chain } });
};

const linkWallet = async (request, reply) => {
  const { chain, address, message, signature } = request.body;
  if (!chain || !address || !message || !signature)
    throw new CustomError('All fields required', 400, true, 'VALIDATION_ERROR');

  const nonceMatch = message.match(/Nonce:\s*([a-f0-9]+)/i);
  if (!nonceMatch) throw new CustomError('No nonce', 400, true, 'NO_NONCE');

  const nonceDoc = await Nonce.consumeNonce(nonceMatch[1], chain, address);
  if (!nonceDoc) throw new CustomError('Invalid nonce', 401, true, 'INVALID_NONCE');

  let verifiedAddress;
  if (chain === 'ethereum') {
    const result = await verifySIWESignature(message, signature, nonceMatch[1], request.hostname || 'localhost');
    verifiedAddress = result.address;
  } else if (chain === 'solana') {
    const result = verifySolanaSignature(message, signature, address);
    if (!result.valid) throw new CustomError('Invalid signature', 401, true, 'VERIFY_FAILED');
    verifiedAddress = result.address;
  } else if (chain === 'bitcoin') {
    const result = await verifyBitcoinSignature(message, address, signature);
    if (!result.valid) throw new CustomError('Invalid signature', 401, true, 'VERIFY_FAILED');
    verifiedAddress = result.address;
  }

  const normalizedAddress = chain === 'ethereum' ? verifiedAddress.toLowerCase() : verifiedAddress;
  const existingUser = await User.findByWallet(chain, normalizedAddress);
  if (existingUser && existingUser._id.toString() !== request.userId) {
    throw new CustomError('Wallet linked to another account', 409, true, 'WALLET_CONFLICT');
  }

  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  if (user.wallets.find(w => w.chain === chain && w.address === normalizedAddress)) {
    throw new CustomError('Already linked', 400, true, 'ALREADY_LINKED');
  }

  let displayName = null;
  if (chain === 'ethereum') displayName = await lookupENS(verifiedAddress);

  user.wallets.push({ chain, address: normalizedAddress, displayName, linkedAt: new Date(), lastUsedAt: new Date() });
  await user.save();

  reply
    .code(200)
    .send({ success: true, data: { user: formatUser(user), linkedWallet: { chain, address: normalizedAddress } } });
};

const getWallets = async (request, reply) => {
  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  reply.code(200).send({
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

const unlinkWallet = async (request, reply) => {
  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  if (user.wallets.length <= 1) throw new CustomError('Cannot unlink last wallet', 400, true, 'LAST_WALLET');

  const idx = user.wallets.findIndex(w => w._id.toString() === request.params.id);
  if (idx === -1) throw new CustomError('Wallet not found', 404, true, 'WALLET_NOT_FOUND');

  const removed = user.wallets.splice(idx, 1)[0];
  if (user.primaryWallet.address === removed.address) {
    user.primaryWallet = { chain: user.wallets[0].chain, address: user.wallets[0].address };
  }
  await user.save();

  reply.code(200).send({ success: true, data: { message: 'Wallet unlinked', user: formatUser(user) } });
};

export { getNonce, verify, linkWallet, getWallets, unlinkWallet };
