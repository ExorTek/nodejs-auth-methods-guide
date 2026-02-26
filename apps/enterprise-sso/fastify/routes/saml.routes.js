import { initiate, assertionConsumerService, metadata, defaultMetadata } from '../controllers/saml.controller.js';

/**
 * SAML routes — Fastify plugin
 */
function samlRoutes(fastify, options, done) {
  // Start SAML SP-initiated flow
  fastify.post('/saml/init', initiate);

  // Assertion Consumer Service — IdP POSTs SAMLResponse here
  fastify.post('/saml/acs', assertionConsumerService);

  // SP Metadata — default
  fastify.get('/saml/metadata', defaultMetadata);

  // SP Metadata — per config
  fastify.get('/saml/metadata/:configId', metadata);

  done();
}

export default samlRoutes;
