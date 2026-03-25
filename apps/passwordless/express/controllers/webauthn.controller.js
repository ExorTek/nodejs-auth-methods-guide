import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { CustomError, logger } from '@auth-guide/shared';
import User from '../models/User.js';
import { createTokenPair, sendTokenResponse, formatUser } from '../utils/token.js';

const RP_NAME = process.env.RP_NAME || 'AuthGuide';
const RP_ID = process.env.RP_ID || 'localhost';
const RP_ORIGIN = process.env.RP_ORIGIN || 'http://localhost:3008';

/**
 *
 * Generate registration options for the WebAuthn ceremony.
 * Client passes these to navigator.credentials.create()
 *
 * Requires existing user (must be logged in or provide email).
 */
const registrationOptions = async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  // Exclude already-registered credentials to prevent re-registration
  const excludeCredentials = user.credentials.map(cred => ({
    id: cred.credentialId,
    type: 'public-key',
    transports: cred.transports,
  }));

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: user.email,
    userDisplayName: user.username,
    // Prefer platform authenticators (fingerprint, Face ID) over roaming (USB key)
    authenticatorSelection: {
      residentKey: 'discouraged',
      userVerification: 'discouraged',
    },
    excludeCredentials,
    attestationType: 'none', // We don't need attestation for most use cases
  });

  // Store challenge for verification
  user.currentChallenge = options.challenge;
  await user.save();

  res.json({ success: true, data: options });
};

/**
 *
 * Verify the registration response from navigator.credentials.create().
 * If valid, store the public key credential.
 */
const registrationVerify = async (req, res) => {
  const { body } = req;

  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  if (!user.currentChallenge) {
    throw new CustomError('No registration challenge found. Call /register/options first.', 400, true, 'NO_CHALLENGE');
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: RP_ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: false,
    });
  } catch (err) {
    console.log(err);
    throw new CustomError(`Registration verification failed: ${err.message}`, 400, true, 'WEBAUTHN_VERIFY_FAILED');
  }

  if (!verification.verified || !verification.registrationInfo) {
    throw new CustomError('Registration verification failed', 400, true, 'WEBAUTHN_VERIFY_FAILED');
  }

  const { credential } = verification.registrationInfo;

  // Store credential
  user.credentials.push({
    credentialId: credential.id,
    publicKey: Buffer.from(credential.publicKey).toString('base64url'),
    counter: credential.counter,
    transports: body.response?.transports || [],
    deviceName: req.body.deviceName || 'Passkey',
    registeredAt: new Date(),
  });

  if (!user.providers.includes('webauthn')) {
    user.providers.push('webauthn');
  }

  // Clear challenge
  user.currentChallenge = null;
  await user.save();

  logger.info({ msg: 'Passkey registered', userId: user._id, credentialId: credential.id });

  res.json({
    success: true,
    data: {
      message: 'Passkey registered successfully!',
      credential: {
        id: credential.id,
        deviceName: req.body.deviceName || 'Passkey',
      },
    },
  });
};

/**
 *
 * Generate authentication options.
 * If email provided, generate options for that user's credentials.
 * If no email, generate discoverable credential options (passkey autofill).
 */
const authenticationOptions = async (req, res) => {
  const { email } = req.body;

  let allowCredentials = [];

  if (email) {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (user && user.credentials.length > 0) {
      allowCredentials = user.credentials.map(cred => ({
        id: cred.credentialId,
        type: 'public-key',
        transports: cred.transports,
      }));
    }
    // Don't throw if user not found — don't leak email existence
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
    userVerification: 'preferred',
  });

  // Store challenge in session-like mechanism
  // For simplicity, store in a temporary map (use Redis in production)
  challengeStore.set(options.challenge, {
    email: email?.toLowerCase() || null,
    createdAt: Date.now(),
  });

  res.json({ success: true, data: options });
};

/**
 *
 * Verify the authentication response from navigator.credentials.get().
 * Find user by credential ID, verify signature, issue JWT.
 */
const authenticationVerify = async (req, res) => {
  const { body } = req;

  // Find user by credential ID
  const credentialId = body.id;
  const user = await User.findOne({ 'credentials.credentialId': credentialId });

  if (!user) {
    throw new CustomError('No account found for this passkey', 401, true, 'CREDENTIAL_NOT_FOUND');
  }

  const storedCredential = user.credentials.find(c => c.credentialId === credentialId);
  if (!storedCredential) {
    throw new CustomError('Credential not found', 401, true, 'CREDENTIAL_NOT_FOUND');
  }

  // Find the challenge — try from challenge store
  const clientData = JSON.parse(Buffer.from(body.response.clientDataJSON, 'base64url').toString());
  const incomingChallenge = clientData.challenge;

  if (!challengeStore.has(incomingChallenge)) {
    throw new CustomError('Invalid or expired challenge', 400, true, 'NO_CHALLENGE');
  }
  const challengeData = challengeStore.get(incomingChallenge);
  if (Date.now() - challengeData.createdAt > 5 * 60 * 1000) {
    challengeStore.delete(incomingChallenge);
    throw new CustomError('Challenge expired', 400, true, 'CHALLENGE_EXPIRED');
  }
  const expectedChallenge = incomingChallenge;

  if (!expectedChallenge) {
    throw new CustomError('No authentication challenge found', 400, true, 'NO_CHALLENGE');
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: RP_ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: storedCredential.credentialId,
        publicKey: Buffer.from(storedCredential.publicKey, 'base64url'),
        counter: storedCredential.counter,
      },
      requireUserVerification: false,
    });
  } catch (err) {
    throw new CustomError(`Authentication verification failed: ${err.message}`, 401, true, 'WEBAUTHN_AUTH_FAILED');
  }

  if (!verification.verified) {
    throw new CustomError('Authentication verification failed', 401, true, 'WEBAUTHN_AUTH_FAILED');
  }

  // Update counter (replay protection)
  storedCredential.counter = verification.authenticationInfo.newCounter;
  storedCredential.lastUsedAt = new Date();
  await user.save();

  // Consume challenge
  challengeStore.delete(expectedChallenge);

  // Issue JWT session
  const tokens = await createTokenPair({ userId: user._id.toString(), username: user.username, req });

  logger.info({ msg: 'Passkey authentication successful', userId: user._id, credentialId });

  sendTokenResponse(res, {
    statusCode: 200,
    ...tokens,
    data: { user: formatUser(user) },
  });
};

/**
 * List user's registered passkeys
 */
const listCredentials = async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const credentials = user.credentials.map(c => ({
    id: c._id,
    credentialId: c.credentialId.slice(0, 16) + '...',
    deviceName: c.deviceName,
    registeredAt: c.registeredAt,
    lastUsedAt: c.lastUsedAt,
    transports: c.transports,
  }));

  res.json({ success: true, data: { credentials, count: credentials.length } });
};

/**
 * Remove a passkey
 */
const deleteCredential = async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const credIndex = user.credentials.findIndex(c => c._id.toString() === req.params.id);
  if (credIndex === -1) {
    throw new CustomError('Credential not found', 404, true, 'CREDENTIAL_NOT_FOUND');
  }

  user.credentials.splice(credIndex, 1);

  // If no credentials left, remove webauthn from providers
  if (user.credentials.length === 0) {
    user.providers = user.providers.filter(p => p !== 'webauthn');
  }

  await user.save();

  logger.info({ msg: 'Passkey removed', userId: user._id });
  res.json({ success: true, data: { message: 'Passkey removed.' } });
};

const challengeStore = new Map();

// Garbage collection
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of challengeStore) {
    if (now - value.createdAt > 5 * 60 * 1000) challengeStore.delete(key);
  }
}, 60 * 1000);

export {
  registrationOptions,
  registrationVerify,
  authenticationOptions,
  authenticationVerify,
  listCredentials,
  deleteCredential,
};
