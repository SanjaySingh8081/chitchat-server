const express = require("express");
const router = express.Router();
const Message = require("../models/Message");
const authMiddleware = require("../middleware/authMiddleware");

// 🗑 Delete message (for everyone)
router.delete("/:id", authMiddleware, async (req, res) => {
  try {
    const message = await Message.findById(req.params.id);
    if (!message) {
      return res.status(404).json({ msg: "Message not found" });
    }

    // Ensure only sender can delete
    if (message.sender.toString() !== req.user.id) {
      return res.status(401).json({ msg: "Not authorized" });
    }

    const { sender, recipient, _id } = message;

    await message.deleteOne();

    // ✅ Emit socket event to both users (sender & recipient)
    if (req.io) {
      req.io.to(sender.toString()).emit("message_deleted", { messageId: _id });
      req.io.to(recipient.toString()).emit("message_deleted", { messageId: _id });
    }

    res.json({ msg: "Message deleted for everyone", id: _id });
  } catch (err) {
    console.error("❌ Error deleting message:", err);
    res.status(500).send("Server error");
  }
});

module.exports = router;
