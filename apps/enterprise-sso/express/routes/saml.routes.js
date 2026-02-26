import { Router } from 'express';
import { initiate, assertionConsumerService, metadata, defaultMetadata } from '../controllers/saml.controller.js';

const router = Router();

// Start SAML SP-initiated flow
router.post('/saml/init', initiate);

// Assertion Consumer Service — IdP POSTs SAMLResponse here
// Must accept application/x-www-form-urlencoded (IdP sends form POST)
router.post('/saml/acs', assertionConsumerService);

// SP Metadata — default (from env vars)
router.get('/saml/metadata', defaultMetadata);

// SP Metadata — per config
router.get('/saml/metadata/:configId', metadata);

export default router;
