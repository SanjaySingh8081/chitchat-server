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
app.use(
  cors({
    origin: [
      "http://localhost:5173", // Local dev
      "https://chitchat-frontend-mu.vercel.app", // ✅ Your deployed frontend
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

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

// --- Basic APIs (Contacts, Requests, Profile) ---
app.get("/api/contacts", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate(
      "contacts",
      "-password -__v"
    );
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user.contacts);
  } catch (error) {
    console.error("Get Contacts Error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/profile/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (error) {
    res.status(500).send("Server Error");
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


// --- Server + Socket.io Setup ---
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: [
      "http://localhost:5173",
      "https://chitchat-frontend-mu.vercel.app",
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
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

  // --- Handle Sending Messages ---
  socket.on("send_message", async (data) => {
    try {
      const newMessage = new Message({
        sender: socket.userId,
        recipient: data.recipientId,
        content: data.content,
      });
      const savedMessage = await newMessage.save();

      const recipientSocketId = onlineUsers[data.recipientId];
      if (recipientSocketId)
        io.to(recipientSocketId).emit("receive_message", savedMessage);

      io.to(socket.id).emit("receive_message", savedMessage);
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
