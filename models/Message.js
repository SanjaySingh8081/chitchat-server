const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema(
  {
    sender: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    recipient: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    content: {
      type: String,
      required: true,
      trim: true
    },

    // 👇 New field for WhatsApp-style message states
    status: {
      type: String,
      enum: ['sent', 'delivered', 'seen'], // ✅ message states
      default: 'sent'
    },

    // 👇 Optional timestamps for more realistic behavior
    deliveredAt: {
      type: Date,
      default: null
    },
    seenAt: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: true // adds createdAt, updatedAt automatically
  }
);

const Message = mongoose.model('Message', messageSchema);

module.exports = Message;
