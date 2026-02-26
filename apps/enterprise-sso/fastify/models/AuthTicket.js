import mongoose from 'mongoose';
import { sha256 } from '@auth-guide/shared';

/**
 * AuthTicket — bridges the gap between OAuth callback and frontend
 *
 * Problem: After OAuth callback, we can't safely deliver JWT tokens.
 *   - JSON response → browser shows raw JSON, SPA can't catch it
 *   - Token in URL query → visible in browser history, server logs, Referer header
 *   - Token in URL fragment (#) → better, but still in browser history
 *
 * Solution (Ticket Exchange Pattern):
 *   1. OAuth callback → create short-lived ticket → redirect to frontend with ?ticket=xxx
 *   2. Frontend → POST /api/auth/exchange { ticket } → receive JWT tokens in headers
 *   3. Ticket is consumed (one-time use, 30-sec TTL)
 */
const authTicketSchema = new mongoose.Schema(
  {
    ticketHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    isUsed: {
      type: Boolean,
      default: false,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expireAfterSeconds: 0 }, // MongoDB auto-deletes expired docs
    },
    userAgent: {
      type: String,
      default: null,
    },
    ip: {
      type: String,
      default: null,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

/**
 * Consume ticket atomically — one-time use
 * findOneAndUpdate ensures only one request can consume the same ticket
 */
authTicketSchema.statics.consumeTicket = async function (plainTicket) {
  return this.findOneAndUpdate(
    {
      ticketHash: sha256(plainTicket),
      isUsed: false,
      expiresAt: { $gt: new Date() },
    },
    { isUsed: true },
    { returnDocument: 'before' },
  );
};

export default mongoose.model('AuthTicket', authTicketSchema);
