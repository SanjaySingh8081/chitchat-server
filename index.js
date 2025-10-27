// --- Load Environment Variables ---
require("dotenv").config();

// --- Core Imports ---
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// --- Models and Config ---
const User = require("./models/User");
const Message = require("./models/Message");
const ContactRequest = require("./models/ContactRequest");
const authMiddleware = require("./middleware/authMiddleware");
const upload = require("./config/cloudinary");
const messageRoutes = require("./routes/messageRoutes");

// --- Initialize Express ---
const app = express();
app.use(express.json());

// --- CORS Setup ---
app.use(cors({
  origin: [
    "http://localhost:5173", 
    "https://chitchat-frontend-mu.vercel.app" // ✅ your real frontend URL
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "x-auth-token"],
  credentials: true,
}));

// --- Database Connection ---
const MONGO_URI =
  process.env.MONGO_URI || "mongodb://127.0.0.1:27017/chitchatDB";

mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log(`✅ Connected to MongoDB: ${MONGO_URI}`))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// --- Routes ---
app.use("/api/messages", messageRoutes);

// --- Auth and Profile APIs ---
app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res
        .status(400)
        .json({ message: "User with this email already exists." });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    console.error("Registration Error:", error);
    res.status(500).json({ message: "Server error during registration." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid credentials." });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials." });

    const token = jwt.sign(
      { user: { id: user.id } },
      process.env.JWT_SECRET || "a_default_secret_key",
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "Server error during login." });
  }
});

app.get("/api/contacts", authMiddleware, async (req, res) => {
  try {
    const myUserId = req.user.id;

    // Find current user with their accepted contacts list
    const me = await User.findById(myUserId).populate("contacts", "name email avatarUrl isOnline lastSeen");

    if (!me || !me.contacts || me.contacts.length === 0) {
      return res.json([]); // no contacts yet
    }

    const contacts = me.contacts;

    // Fetch the latest message between current user and each contact
    const contactData = await Promise.all(
      contacts.map(async (user) => {
        const lastMessage = await Message.findOne({
          $or: [
            { sender: myUserId, recipient: user._id },
            { sender: user._id, recipient: myUserId },
          ],
        })
          .sort({ createdAt: -1 })
          .select("content sender createdAt");

        return {
          ...user.toObject(),
          lastMessageAt: lastMessage ? lastMessage.createdAt : null,
          lastMessageContent: lastMessage ? lastMessage.content : "",
          lastMessageFromMe: lastMessage ? lastMessage.sender.toString() === myUserId : false,
        };
      })
    );

    // Sort by last message time (latest first)
    contactData.sort(
      (a, b) => new Date(b.lastMessageAt || 0) - new Date(a.lastMessageAt || 0)
    );

    res.json(contactData);
  } catch (error) {
    console.error("Error fetching contacts:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.put('/api/profile/me', authMiddleware, async (req, res) => {
  try {
    const { name, about, avatarUrl, phoneNumber } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { name, about, avatarUrl, phoneNumber },
      { new: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({ msg: 'User not found' });
    }

    // ✅ Emit "profile_updated" event via Socket.io
    const io = req.app.get('io'); // Make sure you set this in server.js
    if (io) {
      io.emit('profile_updated', {
        _id: updatedUser._id,
        name: updatedUser.name,
        about: updatedUser.about,
        avatarUrl: updatedUser.avatarUrl,
        phoneNumber: updatedUser.phoneNumber,
      });
    }

    res.json(updatedUser);
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).send('Server Error');
  }
});

// --- Get Current User Profile ---
app.get('/api/profile/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ message: 'Server error' });
  }
});



app.get('/api/messages/:otherUserId', authMiddleware, async (req, res) => {
  try {
    const myUserId = req.user.id;
    const otherUserId = req.params.otherUserId;
    const messages = await Message.find({
      $or: [
        { sender: myUserId, recipient: otherUserId },
        { sender: otherUserId, recipient: myUserId }
      ],
    }).sort({ createdAt: 'asc' });
    res.json(messages);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users/search', authMiddleware, async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) {
      return res.status(400).json({ message: 'Email query is required' });
    }
    const users = await User.find({ 
      email: { $regex: email, $options: 'i' },
      _id: { $ne: req.user.id }
    }).select('-password');
    res.json(users);
  } catch (error) {
    console.error('User Search Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/contact-requests/send/:userId', authMiddleware, async (req, res) => {
  try {
    const toUser = req.params.userId;
    const fromUser = req.user.id;
    
    if (toUser === fromUser) {
        return res.status(400).json({ message: 'You cannot send a contact request to yourself.' });
    }

    const sender = await User.findById(fromUser);
    if (sender.contacts.includes(toUser)) {
      return res.status(400).json({ message: 'User is already in your contacts.' });
    }

    const existingRequest = await ContactRequest.findOne({
      $or: [
        { fromUser: fromUser, toUser: toUser },
        { fromUser: toUser, toUser: fromUser }
      ]
    });
    if (existingRequest) {
      return res.status(400).json({ message: 'A contact request already exists between you and this user.' });
    }

    const newRequest = new ContactRequest({ fromUser, toUser });
    await newRequest.save();
    res.status(201).json({ message: 'Contact request sent successfully.' });
  } catch (error) {
    console.error('Send Request Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/contact-requests/:requestId/respond', authMiddleware, async (req, res) => {
  try {
    const { requestId } = req.params;
    const { response } = req.body; // 'accept' or 'decline'
    const toUser = req.user.id;

    const request = await ContactRequest.findById(requestId);
    if (!request || request.toUser.toString() !== toUser) {
      return res.status(404).json({ message: 'Request not found or you are not authorized.' });
    }

    if (response === 'accept') {
      request.status = 'accepted';
      await request.save();

      await User.findByIdAndUpdate(toUser, { $addToSet: { contacts: request.fromUser } });
      await User.findByIdAndUpdate(request.fromUser, { $addToSet: { contacts: toUser } });
      
      return res.json({ message: 'Contact request accepted.' });
    } else if (response === 'decline') {
      request.status = 'declined';
      await request.save();
      return res.json({ message: 'Contact request declined.' });
    } else {
      return res.status(400).json({ message: 'Invalid response.' });
    }
  } catch (error) {
    console.error('Respond to Request Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/contact-requests/pending', authMiddleware, async (req, res) => {
  try {
    const requests = await ContactRequest.find({
      toUser: req.user.id,
      status: 'pending'
    }).populate('fromUser', 'name email avatarUrl');
    res.json(requests);
  } catch (error) {
    console.error('Get Pending Requests Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/profile/avatar', authMiddleware, (req, res) => {
  const uploader = upload.single('avatar');
  uploader(req, res, function (err) {
    if (err) {
      console.error('--- CLOUDINARY UPLOAD ERROR ---');
      console.error(err);
      return res.status(500).json({ message: 'File upload failed.', error: err.message });
    }
    if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
    res.json({ avatarUrl: req.file.path });
  });
});


// --- Server + Socket.io Setup ---
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: [
      "http://localhost:5173", // local dev
      "https://chitchat-frontend-mu.vercel.app", // deployed frontend ✅
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], // ✅ added OPTIONS
    allowedHeaders: ["Content-Type", "x-auth-token"], // ✅ allow auth + JSON
    credentials: true, // ✅ allow cookies/tokens if ever needed
  },
});

app.set("io", io);

// --- Socket.io Authentication ---
const onlineUsers = {};

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error("Authentication error"));
  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "a_default_secret_key"
    );
    socket.userId = decoded.user.id;
    next();
  } catch (err) {
    console.error("Invalid socket token:", err.message);
    next(new Error("Authentication error"));
  }
});

io.on("connection", async (socket) => {
  console.log(`🟢 User Connected: ${socket.id} (User ID: ${socket.userId})`);

  await User.findByIdAndUpdate(socket.userId, { isOnline: true });
  onlineUsers[socket.userId] = socket.id;

  socket.broadcast.emit("user_online", { userId: socket.userId });

  socket.on("message_status_update", (data) => {
  console.log("📩 Message status updated:", data);
});


  
 // --- Handle Sending Messages (with status tracking) ---
// --- Handle Sending Messages (WhatsApp-style status tracking) ---
socket.on("send_message", async (data) => {
  try {
    const { recipientId, content } = data;

    // 1️⃣ Create new message with default "sent" status
    const newMessage = new Message({
      sender: socket.userId,
      recipient: recipientId,
      content,
      status: "sent",
      sentAt: new Date(),
    });

    const savedMessage = await newMessage.save();

    // 2️⃣ Always send message to the sender’s chat window
    io.to(socket.id).emit("receive_message", savedMessage);

    // 3️⃣ Check if recipient is online
    const recipientSocketId = onlineUsers[recipientId];

    if (recipientSocketId) {
      // ✅ Mark as "delivered"
      savedMessage.status = "delivered";
      savedMessage.deliveredAt = new Date();
      await savedMessage.save();

      // ✅ Send message to recipient immediately
      io.to(recipientSocketId).emit("receive_message", {
        ...savedMessage.toObject(),
        status: "delivered",
      });

      // ✅ Notify sender that message was delivered
      io.to(socket.id).emit("message_status_update", {
        messageId: savedMessage._id,
        status: "delivered",
        chatWith: recipientId,
      });
    } else {
      // ❌ Recipient offline → stays "sent"
      io.to(socket.id).emit("message_status_update", {
        messageId: savedMessage._id,
        status: "sent",
        chatWith: recipientId,
      });
    }
  } catch (error) {
    console.error("❌ Error saving or sending message:", error);
  }
});


  // --- Handle Typing Notifications ---
  socket.on("typing", (data) => {
    const recipientSocketId = onlineUsers[data.recipientId];
    if (recipientSocketId)
      io.to(recipientSocketId).emit("typing_notification", {
        senderId: socket.userId,
      });
  });

// --- Handle mark_seen event (only when user opens the chat) ---
socket.on("mark_seen", async ({ chatWith }) => {
  try {
    if (!chatWith) return;

    // 1️⃣ Update only messages that were delivered but not yet seen
    const unseenMessages = await Message.find({
      sender: chatWith,
      recipient: socket.userId,
      status: { $ne: "seen" },
    });

    if (unseenMessages.length > 0) {
      // Mark them as seen
      await Message.updateMany(
        { _id: { $in: unseenMessages.map((m) => m._id) } },
        { $set: { status: "seen" } }
      );

      // 2️⃣ Notify sender for each seen message
      const senderSocket = onlineUsers[chatWith];
      if (senderSocket) {
        unseenMessages.forEach((msg) => {
          io.to(senderSocket).emit("message_status_update", {
            messageId: msg._id,
            status: "seen",
            chatWith: socket.userId,
          });
        });
      }
    }
  } catch (error) {
    console.error("❌ Error in mark_seen:", error);
  }
});



  // --- Handle Message Deletion ---
  socket.on("delete_message", async (messageId) => {
    try {
      const message = await Message.findById(messageId);
      if (!message) return;

      await Message.deleteOne({ _id: messageId });

      const senderSocket = onlineUsers[message.sender?.toString()];
      const recipientSocket = onlineUsers[message.recipient?.toString()];

      if (senderSocket)
        io.to(senderSocket).emit("message_deleted", { messageId });
      if (recipientSocket)
        io.to(recipientSocket).emit("message_deleted", { messageId });
    } catch (error) {
      console.error("❌ Error deleting message:", error);
    }
  });

  // --- Handle Disconnect ---
  socket.on("disconnect", async () => {
    await User.findByIdAndUpdate(socket.userId, {
      isOnline: false,
      lastSeen: new Date(),
    });

    delete onlineUsers[socket.userId];

    socket.broadcast.emit("user_offline", {
      userId: socket.userId,
      lastSeen: new Date(),
    });
  });
});

// --- Server Start ---
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
