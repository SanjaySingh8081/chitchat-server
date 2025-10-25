
const mongoose = require('mongoose');


const messageSchema = new mongoose.Schema({
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
  // 'type' is removed, as we are only handling text for now
}, {
  timestamps: true
});

const Message = mongoose.model('Message', messageSchema);

module.exports = Message;