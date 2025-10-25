require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
import cors from "cors";
const cors = require("cors");

app.use(cors({
  origin: [
    "http://localhost:5173",  // local dev
    "https://chitchat-frontend-mu.vercel.app" // ✅ your deployed frontend
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const Message = require('./models/Message');
const ContactRequest = require('./models/ContactRequest');
const authMiddleware = require('./middleware/authMiddleware');
const upload = require('./config/cloudinary');
const messageRoutes = require("./routes/messageRoutes");


// --- Database Connection ---
// --- Database Connection ---
// --- Database Connection ---
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/chitchatDB";

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log(`✅ Connected to MongoDB: ${MONGO_URI}`))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// -------------------------


const app = express();
app.use(cors());
app.use(express.json());
app.use("/api/messages", messageRoutes);


// --- API Routes ---
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User with this email already exists.' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = new User({
      email,
      password: hashedPassword,
    });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    console.error('Registration Error:', error);
    res.status(500).json({ message: 'Server error during registration.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }
    const payload = {
      user: {
        id: user.id,
      },
    };
    jwt.sign(
      payload,
      process.env.JWT_SECRET || 'a_default_secret_key',
      { expiresIn: '1h' },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ message: 'Server error during login.' });
  }
});

app.get('/api/contacts', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate('contacts', '-password -__v');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user.contacts);
  } catch (error) {
    console.error('Get Contacts Error:', error);
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

app.get('/api/messages/:otherUserId', authMiddleware, async (req, res) => {
  try {
    const myUserId = req.user.id;
    const otherUserId = req.params.otherUserId;
    const messages = await Message.find({
      $or: [{ sender: myUserId, recipient: otherUserId }, { sender: otherUserId, recipient: myUserId }],
    }).sort({ createdAt: 'asc' });
    res.json(messages);
  } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/profile/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (error) { res.status(500).send('Server Error'); }
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
// -----------------

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: [
      "http://localhost:5173",
      "https://chitchat-frontend-mu.vercel.app"
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  },
});


// ✅ Make io available globally to Express routes
app.set('io', io);

const onlineUsers = {};

// --- Socket Middleware for Authentication ---
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error'));

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'a_default_secret_key');
    socket.userId = decoded.user.id;
    next();
  } catch (err) {
    console.error('Invalid socket token:', err.message);
    return next(new Error('Authentication error'));
  }
});

io.on('connection', async (socket) => {
  console.log(`🟢 User Connected: ${socket.id} (User ID: ${socket.userId})`);

  await User.findByIdAndUpdate(socket.userId, { isOnline: true });
  onlineUsers[socket.userId] = socket.id;

  socket.broadcast.emit('user_online', { userId: socket.userId });

  // --- Handle Sending Messages ---
  socket.on('send_message', async (data) => {
    try {
      const newMessage = new Message({
        sender: socket.userId,
        recipient: data.recipientId,
        content: data.content,
      });

      const savedMessage = await newMessage.save();

      const recipientSocketId = onlineUsers[data.recipientId];
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('receive_message', savedMessage);
      }

      io.to(socket.id).emit('receive_message', savedMessage);
    } catch (error) {
      console.error("❌ Error saving or sending message:", error);
    }
  });

  // --- Handle Typing Notifications ---
  socket.on('typing', (data) => {
    const recipientSocketId = onlineUsers[data.recipientId];
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('typing_notification', { senderId: socket.userId });
    }
  });

 // 🗑️ Handle message deletion and notify both users
// 🗑️ Handle message deletion and notify both users
// 🗑️ Handle message deletion and notify both users
// 🗑️ Handle message deletion and notify both users
// 🗑️ Handle message deletion and notify both users
// 🗑️ Handle message deletion and notify both users in real-time
socket.on("delete_message", async (messageId) => {
  console.log("🗑️ Delete request received for:", messageId);

  try {
    const message = await Message.findById(messageId);

    if (!message) {
      console.log("❌ Message not found in DB");
      return;
    }

    const { sender, recipient, _id } = message;

    // Delete the message from MongoDB
    await Message.deleteOne({ _id });

    // Confirm deletion on both ends
    const senderSocketId = onlineUsers[sender?.toString()];
    const recipientSocketId = onlineUsers[recipient?.toString()];

    console.log(
      "📤 Emitting deletion to:",
      "\n Sender:", senderSocketId,
      "\n Recipient:", recipientSocketId
    );

    // Emit to both users so it updates instantly
    if (senderSocketId) io.to(senderSocketId).emit("message_deleted", { messageId: _id });
    if (recipientSocketId) io.to(recipientSocketId).emit("message_deleted", { messageId: _id });

    console.log("✅ Message deleted for everyone:", _id);
  } catch (error) {
    console.error("❌ Error deleting message:", error);
  }
});





  // --- Handle Real-Time Profile Updates ---
  socket.on('profile_updated', (updatedUser) => {
    console.log(`👤 Profile updated for user ${updatedUser._id}`);
    socket.broadcast.emit('profile_updated', updatedUser);
  });

  // --- Handle Disconnect ---
  socket.on('disconnect', async () => {
    console.log(`🔴 User Disconnected: ${socket.id}`);
    const lastSeenTime = new Date();

    await User.findByIdAndUpdate(socket.userId, {
      isOnline: false,
      lastSeen: lastSeenTime,
    });

    delete onlineUsers[socket.userId];

    socket.broadcast.emit('user_offline', {
      userId: socket.userId,
      lastSeen: lastSeenTime,
    });
  });
});

// --- Server Start ---
// --- Server Start ---
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

