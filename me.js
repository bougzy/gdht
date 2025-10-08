// ================== IMPORTS ==================
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const path = require("path");
const cors = require("cors");
const WebSocket = require('ws');
const http = require('http');
const multer = require('multer');
const requestIp = require('request-ip');
const geoip = require('geoip-lite');
const fs = require('fs');

// ================== APP SETUP ==================
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Enhanced CORS configuration
app.use(cors({
  origin: process.env.CLIENT_URL || "mongodb+srv://trader:trader@trader.wuudnoj.mongodb.net/trader",
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Admin-Username', 'Admin-Password']
}));

app.use(requestIp.mw());
const server = http.createServer(app);

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// ================== DB CONNECTION ==================
mongoose.connect(process.env.MONGO_URI || "mongodb+srv://montracorp:montracorp@montracorp.ypvutxx.mongodb.net/montracorp", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("MongoDB connected successfully"))
  .catch(err => console.error("MongoDB connection error:", err));

// ================== MODELS ==================

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, select: false, required: true },
  confirmPassword: { type: String, select: false },
  secretQuestion: { type: String, required: true },
  secretAnswer: { type: String, select: false, required: true },
  bitcoinAccount: { type: String },
  tetherTRC20Account: { type: String },
  ipAddress: { type: String },
  location: {
    country: String,
    region: String,
    city: String,
    timezone: String,
    ll: [Number]
  },
  lastLogin: { type: Date },
  loginHistory: [{
    ip: String,
    location: Object,
    timestamp: { type: Date, default: Date.now }
  }],
  role: { type: String, default: "user" },
  walletBalance: { type: Number, default: 0 },
  depositBalance: { type: Number, default: 0 },
  totalInvested: { type: Number, default: 0 },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  referrals: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  referralCode: { type: String, unique: true },
  agreedToTerms: { type: Boolean, default: false },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  isBlocked: { type: Boolean, default: false },
  isVerified: { type: Boolean, default: false },
}, { timestamps: true });

userSchema.pre("save", async function(next) {
  if (this.isModified("password")) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    if (this.confirmPassword) {
      this.confirmPassword = await bcrypt.hash(this.confirmPassword, salt);
    }
  }

  if (this.isModified("secretAnswer")) {
    const salt = await bcrypt.genSalt(10);
    this.secretAnswer = await bcrypt.hash(this.secretAnswer, salt);
  }

  if (!this.referralCode) {
    let code, exists = true;
    while (exists) {
      code = crypto.randomBytes(3).toString("hex");
      const user = await User.findOne({ referralCode: code.toUpperCase() });
      if (!user) exists = false;
    }
    this.referralCode = code.toUpperCase();
  }
  next();
});

userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

userSchema.methods.matchSecretAnswer = async function(enteredAnswer) {
  return await bcrypt.compare(enteredAnswer, this.secretAnswer);
};

const User = mongoose.model("User", userSchema);

// Admin Schema
const adminSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true, select: false },
  role: { type: String, default: "admin" },
  name: { type: String, default: "Admin" }
}, { timestamps: true });

adminSchema.pre("save", async function(next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const Admin = mongoose.model("Admin", adminSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  type: { type: String, enum: ["deposit", "withdrawal", "investment"], required: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
  adminNote: String,
  proof: String,
  processed: { type: Boolean, default: false },
  investmentPlan: String,
  walletAddress: String,
}, { timestamps: true });

const Transaction = mongoose.model("Transaction", transactionSchema);

// Investment Schema
const investmentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  transaction: { type: mongoose.Schema.Types.ObjectId, ref: "Transaction", required: true },
  planName: { type: String, required: true },
  amount: { type: Number, required: true },
  profitRate: { type: Number, required: true },
  expectedProfit: { type: Number, required: true },
  status: { type: String, enum: ["active", "completed", "cancelled"], default: "active" },
  startDate: { type: Date, default: Date.now },
  endDate: Date,
  profits: [{
    amount: Number,
    date: { type: Date, default: Date.now },
    note: String
  }],
  totalProfitEarned: { type: Number, default: 0 }
}, { timestamps: true });

const Investment = mongoose.model("Investment", investmentSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" },
  recipients: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  title: { type: String, required: true },
  content: { type: String, required: true },
  readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  isImportant: { type: Boolean, default: false }
}, { timestamps: true });

const Message = mongoose.model("Message", messageSchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  title: { type: String, required: true },
  content: { type: String, required: true },
  type: { type: String, default: "info" },
  isRead: { type: Boolean, default: false },
  relatedId: mongoose.Schema.Types.ObjectId,
  relatedType: String
}, { timestamps: true });

const Notification = mongoose.model("Notification", notificationSchema);

// Profit Schema
const profitSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  amount: { type: Number, required: true },
  note: String,
  investmentId: { type: mongoose.Schema.Types.ObjectId, ref: "Investment" },
}, { timestamps: true });

const Profit = mongoose.model("Profit", profitSchema);

// ================== MIDDLEWARE ==================
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

// Enhanced file upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || 
        file.mimetype === 'application/pdf' ||
        file.mimetype === 'application/png' ||
        file.mimetype === 'application/jpeg') {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDF files are allowed'), false);
    }
  }
});

const getUserLocation = (ip) => {
  if (ip === '::1' || ip === '127.0.0.1') {
    return {
      country: 'US',
      region: 'California',
      city: 'San Francisco',
      timezone: 'America/Los_Angeles',
      ll: [37.7749, -122.4194]
    };
  }
  
  const geo = geoip.lookup(ip);
  if (geo) {
    return {
      country: geo.country,
      region: geo.region,
      city: geo.city,
      timezone: geo.timezone,
      ll: geo.ll
    };
  }
  
  return null;
};

const updateUserLocation = async (req, res, next) => {
  if (req.user) {
    try {
      const ip = req.clientIp;
      const location = getUserLocation(ip);
      
      await User.findByIdAndUpdate(req.user._id, {
        $set: {
          ipAddress: ip,
          lastLogin: new Date(),
          ...(location && { location: location })
        },
        $push: {
          loginHistory: {
            ip: ip,
            location: location,
            timestamp: new Date()
          }
        }
      });
    } catch (error) {
      console.error('Error updating user location:', error);
    }
  }
  next();
};

// Enhanced authentication middleware
const protect = async (req, res, next) => {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    
    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: "Access denied. No token provided." 
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || "supersecretjwtkey");
    const user = await User.findById(decoded.id).select("-password -secretAnswer -confirmPassword");
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: "User not found." 
      });
    }
    
    if (user.isBlocked) {
      return res.status(403).json({ 
        success: false,
        message: "Account has been blocked. Please contact support." 
      });
    }
    
    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false,
        message: "Invalid token." 
      });
    }
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false,
        message: "Token expired." 
      });
    }
    res.status(500).json({ 
      success: false,
      message: "Server error during authentication." 
    });
  }
};

const adminAuth = async (req, res, next) => {
  try {
    const username = req.headers["admin-username"];
    const password = req.headers["admin-password"];
    
    if (!username || !password) {
      return res.status(401).json({ 
        success: false,
        message: "Admin credentials required" 
      });
    }

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      req.admin = { username };
      return next();
    }
    
    res.status(403).json({ 
      success: false,
      message: "Invalid admin credentials" 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      message: "Admin authentication error" 
    });
  }
};

// ================== UTILS ==================
const generateToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET || "supersecretjwtkey", { expiresIn: "7d" });
};

// Enhanced notification system
const sendNotification = async (userId, title, content, type = "info", relatedId = null, relatedType = null) => {
  try {
    const notif = new Notification({ 
      user: userId, 
      title, 
      content, 
      type,
      relatedId,
      relatedType
    });
    await notif.save();
    
    // Real-time delivery via WebSocket
    sendUserUpdate(userId.toString(), {
      type: 'NEW_NOTIFICATION',
      notification: notif,
      message: 'You have a new notification'
    });
    
    return notif;
  } catch (error) {
    console.error("Error sending notification:", error);
    return null;
  }
};

// Enhanced WebSocket system
const wss = new WebSocket.Server({ 
  server,
  path: '/ws',
  perMessageDeflate: false
});

const clients = new Map();

wss.on('connection', (ws, req) => {
  console.log('New WebSocket connection attempt');
  
  const authTimeout = setTimeout(() => {
    if (!ws.authenticated) {
      ws.send(JSON.stringify({
        type: 'ERROR',
        message: 'Authentication timeout'
      }));
      ws.close();
    }
  }, 5000);

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data);
      
      if (message.type === 'AUTH' && message.token) {
        clearTimeout(authTimeout);
        
        try {
          const decoded = jwt.verify(message.token, process.env.JWT_SECRET || "supersecretjwtkey");
          const userId = decoded.id;
          
          const user = await User.findById(userId);
          if (!user) {
            ws.send(JSON.stringify({
              type: 'ERROR',
              message: 'User not found'
            }));
            return ws.close();
          }
          
          if (user.isBlocked) {
            ws.send(JSON.stringify({
              type: 'ERROR',
              message: 'Account blocked'
            }));
            return ws.close();
          }
          
          clients.set(userId.toString(), ws);
          ws.userId = userId.toString();
          ws.authenticated = true;
          
          ws.send(JSON.stringify({
            type: 'CONNECTED',
            user: {
              id: user._id,
              username: user.username,
              walletBalance: user.walletBalance,
              depositBalance: user.depositBalance
            },
            message: 'WebSocket connected successfully'
          }));
          
          console.log(`User ${userId} connected via WebSocket`);
          
        } catch (authError) {
          ws.send(JSON.stringify({
            type: 'ERROR',
            message: 'Invalid authentication'
          }));
          ws.close();
        }
      }
    } catch (parseError) {
      ws.send(JSON.stringify({
        type: 'ERROR',
        message: 'Invalid message format'
      }));
    }
  });
  
  ws.on('close', () => {
    clearTimeout(authTimeout);
    if (ws.userId) {
      clients.delete(ws.userId);
      console.log(`User ${ws.userId} disconnected from WebSocket`);
    }
  });
  
  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
    clearTimeout(authTimeout);
  });
});

function sendUserUpdate(userId, data) {
  const ws = clients.get(userId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify({
        ...data,
        timestamp: new Date().toISOString()
      }));
    } catch (error) {
      console.error('Error sending WebSocket message:', error);
      clients.delete(userId);
    }
  }
}

function broadcastToUsers(userIds, data) {
  userIds.forEach(userId => sendUserUpdate(userId, data));
}



const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'your_email@gmail.com',
    pass: 'your_password'
  }
});


// ================== CONTROLLERS ==================

// Auth Controllers
const authController = {
  register: async (req, res) => {
    try {
      const {
        username, name, email, password, confirmPassword,
        bitcoinAccount, tetherTRC20Account, secretQuestion,
        secretAnswer, agreedToTerms, referralCode
      } = req.body;

      // Validation
      const missingFields = [];
      if (!username) missingFields.push('username');
      if (!name) missingFields.push('name');
      if (!email) missingFields.push('email');
      if (!password) missingFields.push('password');
      if (!confirmPassword) missingFields.push('confirmPassword');
      if (!secretQuestion) missingFields.push('secretQuestion');
      if (!secretAnswer) missingFields.push('secretAnswer');

      if (missingFields.length > 0) {
        return res.status(400).json({ 
          success: false,
          message: `Missing required fields: ${missingFields.join(', ')}` 
        });
      }

      if (password !== confirmPassword) {
        return res.status(400).json({ 
          success: false,
          message: "Passwords do not match" 
        });
      }

      if (!agreedToTerms) {
        return res.status(400).json({ 
          success: false,
          message: "You must agree to the terms and conditions" 
        });
      }

      if (password.length < 6) {
        return res.status(400).json({ 
          success: false,
          message: "Password must be at least 6 characters long" 
        });
      }

      const existingUser = await User.findOne({ 
        $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }] 
      });
      
      if (existingUser) {
        if (existingUser.email === email.toLowerCase()) {
          return res.status(400).json({ 
            success: false,
            message: "Email already registered" 
          });
        }
        if (existingUser.username === username.toLowerCase()) {
          return res.status(400).json({ 
            success: false,
            message: "Username already taken" 
          });
        }
      }

      const ip = req.clientIp;
      const location = getUserLocation(ip);

      let referredBy = null;
      if (referralCode) {
        const referrer = await User.findOne({ referralCode: referralCode.toUpperCase() });
        if (referrer) referredBy = referrer._id;
      }

      const user = await User.create({
        username: username.toLowerCase(),
        name,
        email: email.toLowerCase(),
        password,
        confirmPassword,
        bitcoinAccount,
        tetherTRC20Account,
        secretQuestion,
        secretAnswer,
        agreedToTerms,
        referredBy,
        ipAddress: ip,
        location: location
      });

      if (referredBy) {
        await User.findByIdAndUpdate(referredBy, { 
          $push: { referrals: user._id } 
        });
      }

      await sendNotification(user._id, "Welcome!", "Thank you for registering with our platform.", "welcome");

      res.status(201).json({
        success: true,
        data: {
          _id: user._id,
          username: user.username,
          name: user.name,
          email: user.email,
          token: generateToken(user._id, user.role)
        },
        message: "Registration successful"
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ 
        success: false,
        message: "Registration failed. Please try again." 
      });
    }
  },

  login: async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email: email.toLowerCase() }).select("+password");
      
      if (user && await user.matchPassword(password)) {
        if (user.isBlocked) {
          return res.status(403).json({ 
            success: false,
            message: "Account blocked. Please contact support." 
          });
        }
        
        const ip = req.clientIp;
        const location = getUserLocation(ip);
        
        await User.findByIdAndUpdate(user._id, {
          $set: {
            ipAddress: ip,
            lastLogin: new Date(),
            ...(location && { location: location })
          },
          $push: {
            loginHistory: {
              ip: ip,
              location: location,
              timestamp: new Date()
            }
          }
        });

        const userResponse = await User.findById(user._id).select("-password -secretAnswer -confirmPassword");

        return res.json({
          success: true,
          data: {
            _id: user._id, 
            username: user.username,
            name: user.name, 
            email: user.email, 
            walletBalance: user.walletBalance,
            depositBalance: user.depositBalance,
            totalInvested: user.totalInvested,
            token: generateToken(user._id, user.role),
            user: userResponse
          },
          message: "Login successful"
        });
      }
      res.status(401).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    } catch (error) { 
      console.error('Login error:', error);
      res.status(500).json({ 
        success: false,
        message: "Login failed. Please try again." 
      }); 
    }
  },

  forgotPassword: async (req, res) => {
    try {
      const { email, secretAnswer } = req.body;
      const user = await User.findOne({ email: email.toLowerCase() }).select("+secretAnswer");
      if (!user) return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });

      if (!await user.matchSecretAnswer(secretAnswer)) {
        return res.status(400).json({ 
          success: false,
          message: "Invalid secret answer" 
        });
      }

      const resetToken = crypto.randomBytes(20).toString("hex");
      user.resetPasswordToken = crypto.createHash("sha256").update(resetToken).digest("hex");
      user.resetPasswordExpire = Date.now() + 10 * 60 * 1000;
      await user.save({ validateBeforeSave: false });

      const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
      await transporter.sendMail({ 
        to: user.email, 
        subject: "Password Reset Request", 
        html: `<p>Click <a href="${resetUrl}">here</a> to reset your password. This link will expire in 10 minutes.</p>` 
      });
      
      res.json({ 
        success: true,
        message: "Password reset link sent to your email" 
      });
    } catch (error) { 
      console.error('Forgot password error:', error);
      res.status(500).json({ 
        success: false,
        message: "Failed to process password reset request" 
      }); 
    }
  },

  resetPassword: async (req, res) => {
    try {
      const token = crypto.createHash("sha256").update(req.params.token).digest("hex");
      const user = await User.findOne({ 
        resetPasswordToken: token, 
        resetPasswordExpire: { $gt: Date.now() } 
      });
      
      if (!user) return res.status(400).json({ 
        success: false,
        message: "Invalid or expired reset token" 
      });
      
      user.password = req.body.password;
      user.confirmPassword = req.body.password;
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save();
      
      await sendNotification(user._id, "Password Reset", "Your password has been successfully reset.", "security");
      
      res.json({ 
        success: true,
        message: "Password reset successful" 
      });
    } catch (error) { 
      console.error('Reset password error:', error);
      res.status(500).json({ 
        success: false,
        message: "Password reset failed" 
      }); 
    }
  }
};

// User Profile Controllers
const profileController = {
  updateProfile: async (req, res) => {
    try {
      const { name, bitcoinAccount, tetherTRC20Account, secretQuestion, secretAnswer } = req.body;
      
      const updateData = {};
      if (name) updateData.name = name;
      if (bitcoinAccount) updateData.bitcoinAccount = bitcoinAccount;
      if (tetherTRC20Account) updateData.tetherTRC20Account = tetherTRC20Account;
      if (secretQuestion) updateData.secretQuestion = secretQuestion;
      if (secretAnswer) {
        const salt = await bcrypt.genSalt(10);
        updateData.secretAnswer = await bcrypt.hash(secretAnswer, salt);
      }

      const updatedUser = await User.findByIdAndUpdate(
        req.user._id,
        updateData,
        { new: true }
      ).select("-password -secretAnswer -confirmPassword");

      await sendNotification(req.user._id, "Profile Updated", "Your profile information has been updated successfully.", "profile");

      res.json({ 
        success: true,
        message: "Profile updated successfully", 
        data: { user: updatedUser } 
      });
    } catch (error) {
      console.error('Profile update error:', error);
      res.status(500).json({ 
        success: false,
        message: "Profile update failed" 
      });
    }
  },

  changePassword: async (req, res) => {
    try {
      const { currentPassword, newPassword, confirmNewPassword } = req.body;
      const user = await User.findById(req.user._id).select("+password");

      if (!await user.matchPassword(currentPassword)) {
        return res.status(400).json({ 
          success: false,
          message: "Current password is incorrect" 
        });
      }

      if (newPassword !== confirmNewPassword) {
        return res.status(400).json({ 
          success: false,
          message: "New passwords do not match" 
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({ 
          success: false,
          message: "New password must be at least 6 characters long" 
        });
      }

      user.password = newPassword;
      user.confirmPassword = newPassword;
      await user.save();

      await sendNotification(user._id, "Password Changed", "Your password has been changed successfully.", "security");

      res.json({ 
        success: true,
        message: "Password changed successfully" 
      });
    } catch (error) {
      console.error('Password change error:', error);
      res.status(500).json({ 
        success: false,
        message: "Password change failed" 
      });
    }
  }
};

// Transaction Controllers
const transactionController = {
  createDeposit: async (req, res) => {
    try {
      const { amount, walletAddress } = req.body;
      const proofFile = req.file;
      
      if (!amount || amount <= 0) {
        return res.status(400).json({ 
          success: false,
          message: "Valid deposit amount is required" 
        });
      }
      
      if (!proofFile) {
        return res.status(400).json({ 
          success: false,
          message: "Proof of payment is required" 
        });
      }
      
      const transaction = await Transaction.create({
        user: req.user._id,
        type: "deposit",
        amount: parseFloat(amount),
        status: "pending",
        proof: proofFile.filename,
        walletAddress: walletAddress || "Default Wallet"
      });
      
      await sendNotification(
        req.user._id,
        "Deposit Submitted",
        `Your deposit of $${amount} has been submitted for approval.`,
        "deposit",
        transaction._id,
        "transaction"
      );
      
      res.json({ 
        success: true,
        message: "Deposit submitted for approval", 
        data: { transaction } 
      });
    } catch (error) {
      console.error('Deposit error:', error);
      res.status(500).json({ 
        success: false,
        message: "Deposit submission failed" 
      });
    }
  },

  createWithdrawal: async (req, res) => {
    try {
      const { amount, walletAddress } = req.body;
      
      if (!amount || amount <= 0) {
        return res.status(400).json({ 
          success: false,
          message: "Valid withdrawal amount is required" 
        });
      }
      
      const user = await User.findById(req.user._id);
      if (user.walletBalance < parseFloat(amount)) {
        return res.status(400).json({ 
          success: false,
          message: "Insufficient wallet balance" 
        });
      }
      
      // Temporary hold on funds
      user.walletBalance -= parseFloat(amount);
      await user.save();
      
      const transaction = await Transaction.create({
        user: req.user._id,
        type: "withdrawal", 
        amount: parseFloat(amount),
        status: "pending",
        walletAddress: walletAddress || "Not specified"
      });
      
      await sendNotification(
        req.user._id,
        "Withdrawal Requested",
        `Your withdrawal request of $${amount} has been submitted for processing.`,
        "withdrawal",
        transaction._id,
        "transaction"
      );

      sendUserUpdate(req.user._id.toString(), {
        type: 'BALANCE_UPDATE',
        walletBalance: user.walletBalance,
        depositBalance: user.depositBalance,
        message: `Withdrawal request of $${amount} submitted`
      });
      
      res.json({ 
        success: true,
        message: "Withdrawal request submitted", 
        data: { transaction } 
      });
    } catch (error) {
      console.error('Withdrawal error:', error);
      res.status(500).json({ 
        success: false,
        message: "Withdrawal request failed" 
      });
    }
  },

  // Enhanced withdrawal approval with success message
  approveWithdrawal: async (req, res) => {
    try {
      const { transactionId } = req.params;
      const { adminNote } = req.body;
      
      const tx = await Transaction.findById(transactionId).populate('user');
      if (!tx || tx.type !== "withdrawal") {
        return res.status(404).json({ 
          success: false,
          message: "Withdrawal transaction not found" 
        });
      }
      
      if (tx.status === "approved") {
        return res.status(400).json({ 
          success: false,
          message: "Withdrawal already approved" 
        });
      }

      // Funds are already held, just update status
      tx.status = "approved";
      if (adminNote) tx.adminNote = adminNote;
      await tx.save();

      await sendNotification(
        tx.user._id,
        "Withdrawal Approved ✅",
        `Your withdrawal of $${tx.amount} has been approved and processed successfully.${adminNote ? ` Note: ${adminNote}` : ''}`,
        "withdrawal",
        tx._id,
        "transaction"
      );

      sendUserUpdate(tx.user._id.toString(), {
        type: 'WITHDRAWAL_APPROVED',
        walletBalance: tx.user.walletBalance,
        transaction: tx,
        message: `Withdrawal of $${tx.amount} approved successfully`
      });

      res.json({ 
        success: true,
        message: "Withdrawal approved successfully", 
        data: { 
          transaction: tx,
          userBalance: {
            walletBalance: tx.user.walletBalance
          }
        }
      });
    } catch (error) { 
      console.error('Withdrawal approval error:', error);
      res.status(500).json({ 
        success: false,
        message: "Withdrawal approval failed" 
      }); 
    }
  },

  // Enhanced withdrawal rejection with failure message
  rejectWithdrawal: async (req, res) => {
    try {
      const { transactionId } = req.params;
      const { adminNote } = req.body;
      
      const tx = await Transaction.findById(transactionId).populate('user');
      if (!tx || tx.type !== "withdrawal") {
        return res.status(404).json({ 
          success: false,
          message: "Withdrawal transaction not found" 
        });
      }
      
      if (tx.status === "rejected") {
        return res.status(400).json({ 
          success: false,
          message: "Withdrawal already rejected" 
        });
      }

      // Return held funds to user
      const user = await User.findById(tx.user._id);
      user.walletBalance += tx.amount;
      await user.save();

      tx.status = "rejected";
      if (adminNote) tx.adminNote = adminNote;
      await tx.save();

      await sendNotification(
        tx.user._id,
        "Withdrawal Rejected ❌",
        `Your withdrawal request of $${tx.amount} has been rejected.${adminNote ? ` Reason: ${adminNote}` : ' Please contact support for more information.'}`,
        "withdrawal",
        tx._id,
        "transaction"
      );

      sendUserUpdate(tx.user._id.toString(), {
        type: 'WITHDRAWAL_REJECTED',
        walletBalance: user.walletBalance,
        transaction: tx,
        message: `Withdrawal of $${tx.amount} was rejected. Funds returned to your wallet.`
      });

      res.json({ 
        success: true,
        message: "Withdrawal rejected successfully", 
        data: { 
          transaction: tx,
          userBalance: {
            walletBalance: user.walletBalance
          }
        }
      });
    } catch (error) { 
      console.error('Withdrawal rejection error:', error);
      res.status(500).json({ 
        success: false,
        message: "Withdrawal rejection failed" 
      }); 
    }
  },

  approveDeposit: async (req, res) => {
    try {
      const { transactionId } = req.params;
      const tx = await Transaction.findById(transactionId).populate('user');
      if (!tx || tx.type !== "deposit") {
        return res.status(404).json({ 
          success: false,
          message: "Deposit transaction not found" 
        });
      }
      
      if (tx.status === "approved") {
        return res.status(400).json({ 
          success: false,
          message: "Deposit already approved" 
        });
      }
      
      tx.status = "approved";
      tx.processed = false;
      await tx.save();
      
      await sendNotification(
        tx.user._id,
        "Deposit Approved ✅",
        `Your deposit of $${tx.amount} has been approved and will be added to your balance shortly.`,
        "deposit",
        tx._id,
        "transaction"
      );
      
      res.json({ 
        success: true,
        message: "Deposit approved successfully", 
        data: { 
          transaction: tx,
          note: "The amount will be added to the user's balance when they check for approved deposits."
        }
      });
    } catch (error) { 
      console.error('Deposit approval error:', error);
      res.status(500).json({ 
        success: false,
        message: "Deposit approval failed" 
      }); 
    }
  },

  rejectDeposit: async (req, res) => {
    try {
      const { transactionId } = req.params;
      const { adminNote } = req.body;
      
      const tx = await Transaction.findById(transactionId).populate('user');
      if (!tx || tx.type !== "deposit") {
        return res.status(404).json({ 
          success: false,
          message: "Deposit transaction not found" 
        });
      }
      
      if (tx.status === "rejected") {
        return res.status(400).json({ 
          success: false,
          message: "Deposit already rejected" 
        });
      }
      
      tx.status = "rejected";
      if (adminNote) tx.adminNote = adminNote;
      await tx.save();
      
      await sendNotification(
        tx.user._id,
        "Deposit Rejected ❌",
        `Your deposit of $${tx.amount} was rejected.${adminNote ? ` Reason: ${adminNote}` : ''}`,
        "deposit",
        tx._id,
        "transaction"
      );
      
      res.json({ 
        success: true,
        message: "Deposit rejected successfully", 
        data: { transaction: tx } 
      });
    } catch (error) { 
      console.error('Deposit rejection error:', error);
      res.status(500).json({ 
        success: false,
        message: "Deposit rejection failed" 
      }); 
    }
  }
};

// Investment Controllers
const investmentController = {
  createInvestment: async (req, res) => {
    try {
      const { planId, amount } = req.body;
      const user = await User.findById(req.user._id);

      const plans = [
        { id: "1", name: "Basic Plan", profitRate: 5, minDeposit: 50, maxDeposit: 1000 },
        { id: "2", name: "Premium Plan", profitRate: 8, minDeposit: 1001, maxDeposit: 5000 },
        { id: "3", name: "VIP Plan", profitRate: 12, minDeposit: 5001, maxDeposit: 20000 }
      ];

      const plan = plans.find(p => p.id === planId);
      if (!plan) return res.status(400).json({ 
        success: false,
        message: "Invalid investment plan" 
      });

      if (user.depositBalance < amount) {
        return res.status(400).json({ 
          success: false,
          message: "Insufficient deposit balance" 
        });
      }

      if (amount < plan.minDeposit || amount > plan.maxDeposit) {
        return res.status(400).json({ 
          success: false,
          message: `Amount must be between $${plan.minDeposit} and $${plan.maxDeposit} for ${plan.name}` 
        });
      }

      const transaction = await Transaction.create({
        user: user._id,
        type: "investment",
        amount: parseFloat(amount),
        status: "pending",
        investmentPlan: plan.name
      });

      await sendNotification(
        user._id,
        "Investment Request Submitted",
        `Your investment request of $${amount} in ${plan.name} has been submitted for approval.`,
        "investment",
        transaction._id,
        "transaction"
      );

      res.json({ 
        success: true,
        message: "Investment request submitted for approval", 
        data: {
          transaction,
          plan: {
            name: plan.name,
            profitRate: plan.profitRate,
            expectedProfit: (amount * plan.profitRate / 100).toFixed(2)
          }
        }
      });
    } catch (error) {
      console.error('Investment creation error:', error);
      res.status(500).json({ 
        success: false,
        message: "Investment request failed" 
      });
    }
  },

  approveInvestment: async (req, res) => {
    try {
      const { transactionId } = req.params;
      const tx = await Transaction.findById(transactionId).populate('user');
      
      if (!tx || tx.type !== "investment") {
        return res.status(404).json({ 
          success: false,
          message: "Investment transaction not found" 
        });
      }
      
      if (tx.status === "approved") {
        return res.status(400).json({ 
          success: false,
          message: "Investment already approved" 
        });
      }

      const user = await User.findById(tx.user._id);
      
      if (user.depositBalance < tx.amount) {
        return res.status(400).json({ 
          success: false,
          message: "User has insufficient deposit balance" 
        });
      }

      const plans = {
        "Basic Plan": { profitRate: 5 },
        "Premium Plan": { profitRate: 8 },
        "VIP Plan": { profitRate: 12 }
      };

      const plan = plans[tx.investmentPlan];
      if (!plan) {
        return res.status(400).json({ 
          success: false,
          message: "Invalid investment plan" 
        });
      }

      user.depositBalance -= tx.amount;
      user.totalInvested += tx.amount;
      await user.save();

      tx.status = "approved";
      await tx.save();

      const expectedProfit = tx.amount * plan.profitRate / 100;
      const investment = await Investment.create({
        user: user._id,
        transaction: tx._id,
        planName: tx.investmentPlan,
        amount: tx.amount,
        profitRate: plan.profitRate,
        expectedProfit: expectedProfit,
        endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      });

      await sendNotification(
        user._id,
        "Investment Approved ✅",
        `Your investment of $${tx.amount} in ${tx.investmentPlan} has been approved. Expected profit: $${expectedProfit.toFixed(2)}`,
        "investment",
        investment._id,
        "investment"
      );

      sendUserUpdate(user._id.toString(), {
        type: 'INVESTMENT_APPROVED',
        walletBalance: user.walletBalance,
        depositBalance: user.depositBalance,
        totalInvested: user.totalInvested,
        investment: investment,
        message: `Your investment of $${tx.amount} has been approved`
      });

      res.json({ 
        success: true,
        message: "Investment approved successfully", 
        data: {
          transaction: tx,
          investment: investment,
          userBalance: {
            walletBalance: user.walletBalance,
            depositBalance: user.depositBalance,
            totalInvested: user.totalInvested
          }
        }
      });
    } catch (error) { 
      console.error('Investment approval error:', error);
      res.status(500).json({ 
        success: false,
        message: "Investment approval failed" 
      }); 
    }
  }
};

// Message Controller
const messageController = {
  sendMessage: async (req, res) => {
    try {
      const { userIds, title, content, isImportant = false } = req.body;

      if (!title || !content) {
        return res.status(400).json({ 
          success: false,
          message: "Title and content are required" 
        });
      }
      
      if (!userIds || userIds.length === 0) {
        return res.status(400).json({ 
          success: false,
          message: "At least one recipient is required" 
        });
      }

      const recipients = Array.isArray(userIds) ? userIds : [userIds];
      
      const users = await User.find({ _id: { $in: recipients } });
      if (users.length !== recipients.length) {
        return res.status(400).json({ 
          success: false,
          message: "Some recipient users were not found" 
        });
      }

      const message = await Message.create({
        sender: null,
        recipients,
        title,
        content,
        isImportant
      });

      const notificationPromises = recipients.map(userId => 
        sendNotification(userId, title, content, "message", message._id, "message")
      );
      
      await Promise.all(notificationPromises);

      broadcastToUsers(recipients, {
        type: 'NEW_MESSAGE',
        message: {
          _id: message._id,
          title,
          content,
          isImportant,
          createdAt: message.createdAt
        }
      });

      res.json({ 
        success: true,
        message: `Message sent successfully to ${recipients.length} user(s)`, 
        data: message 
      });
    } catch (error) {
      console.error('Message sending error:', error);
      res.status(500).json({ 
        success: false,
        message: "Failed to send message" 
      });
    }
  }
};

// ================== ROUTES ==================

// Auth Routes
app.post("/api/register", authController.register);
app.post("/api/login", authController.login);
app.post("/api/forgot-password", authController.forgotPassword);
app.post("/api/reset-password/:token", authController.resetPassword);

// User Profile Routes
app.put("/api/user/profile", protect, updateUserLocation, profileController.updateProfile);
app.put("/api/user/change-password", protect, updateUserLocation, profileController.changePassword);

// User Routes
app.get("/api/me", protect, updateUserLocation, (req, res) => res.json({ 
  success: true, 
  data: { user: req.user } 
}));

app.get("/api/user/transactions", protect, updateUserLocation, async (req, res) => {
  try {
    const transactions = await Transaction.find({ user: req.user._id }).sort({ createdAt: -1 });
    res.json({ success: true, data: transactions });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get("/api/user/referrals", protect, updateUserLocation, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate(
      "referrals",
      "username name email walletBalance depositBalance totalInvested createdAt location"
    );
    res.json({
      success: true,
      data: {
        referralCode: user.referralCode,
        totalReferrals: user.referrals.length,
        referrals: user.referrals
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Investment Routes
app.post("/api/investments", protect, updateUserLocation, investmentController.createInvestment);
app.get("/api/user/investments", protect, updateUserLocation, async (req, res) => {
  try {
    const investments = await Investment.find({ user: req.user._id })
      .populate("transaction")
      .sort({ createdAt: -1 });
    res.json({ success: true, data: investments });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Deposit and Withdrawal Routes
app.post("/api/deposits", protect, updateUserLocation, upload.single('proof'), transactionController.createDeposit);
app.post("/api/withdrawals", protect, updateUserLocation, transactionController.createWithdrawal);

// Notification Routes
app.get("/api/user/notifications", protect, updateUserLocation, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    const notifications = await Notification.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Notification.countDocuments({ user: req.user._id });
    const unreadCount = await Notification.countDocuments({ 
      user: req.user._id, 
      isRead: false 
    });
    
    res.json({
      success: true,
      data: {
        notifications,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        },
        unreadCount
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put("/api/user/notifications/:id/read", protect, updateUserLocation, async (req, res) => {
  try {
    const notif = await Notification.findOneAndUpdate(
      { _id: req.params.id, user: req.user._id },
      { isRead: true },
      { new: true }
    );
    if (!notif) return res.status(404).json({ success: false, message: "Notification not found" });
    res.json({ success: true, data: notif });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put("/api/user/notifications/read-all", protect, updateUserLocation, async (req, res) => {
  try {
    await Notification.updateMany(
      { user: req.user._id, isRead: false },
      { isRead: true }
    );
    res.json({ success: true, message: "All notifications marked as read" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Message Routes
app.get("/api/user/messages", protect, updateUserLocation, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    const messages = await Message.find({ recipients: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .populate("sender", "email role name");
    
    const total = await Message.countDocuments({ recipients: req.user._id });
    
    res.json({
      success: true,
      data: {
        messages,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put("/api/user/messages/:messageId/read", protect, updateUserLocation, async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId);
    
    if (!message) {
      return res.status(404).json({ success: false, message: "Message not found" });
    }
    
    if (!message.readBy.includes(req.user._id)) {
      message.readBy.push(req.user._id);
      await message.save();
    }
    
    res.json({ success: true, message: "Message marked as read" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Investment Plans
app.get("/api/investment-plans", async (req, res) => {
  try {
    const plans = [
      {
        _id: "1",
        name: "Basic Plan",
        profitRate: 5,
        minDeposit: 50,
        maxDeposit: 1000,
        description: "Perfect for beginners with low risk",
        duration: "30 days"
      },
      {
        _id: "2", 
        name: "Premium Plan",
        profitRate: 8,
        minDeposit: 1001,
        maxDeposit: 5000,
        description: "Great returns for serious investors",
        duration: "30 days"
      },
      {
        _id: "3",
        name: "VIP Plan", 
        profitRate: 12,
        minDeposit: 5001,
        maxDeposit: 20000,
        description: "Maximum returns for VIP investors",
        duration: "30 days"
      }
    ];
    res.json({ success: true, data: plans });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Check Approved Deposits
app.get("/api/user/check-approved-deposits", protect, updateUserLocation, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const approvedDeposits = await Transaction.find({
      user: userId,
      type: "deposit",
      status: "approved",
      processed: { $ne: true }
    });
    
    let totalApprovedAmount = 0;
    let processedDeposits = [];
    
    for (const deposit of approvedDeposits) {
      const user = await User.findById(userId);
      user.walletBalance += deposit.amount;
      user.depositBalance += deposit.amount;
      await user.save();
      
      deposit.processed = true;
      await deposit.save();
      
      totalApprovedAmount += deposit.amount;
      processedDeposits.push(deposit);
      
      sendUserUpdate(userId.toString(), {
        type: 'BALANCE_UPDATE',
        walletBalance: user.walletBalance,
        depositBalance: user.depositBalance,
        transaction: deposit,
        message: `Deposit of $${deposit.amount} has been approved and added to your balances`
      });
    }
    
    res.json({
      success: true,
      message: processedDeposits.length > 0 
        ? `Processed ${processedDeposits.length} approved deposits totaling $${totalApprovedAmount}`
        : 'No new approved deposits found',
      data: {
        processedCount: processedDeposits.length,
        totalAmount: totalApprovedAmount,
        walletBalance: req.user.walletBalance + totalApprovedAmount,
        depositBalance: req.user.depositBalance + totalApprovedAmount,
        deposits: processedDeposits
      }
    });
    
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// WebSocket health check
app.get('/api/ws-health', (req, res) => {
  res.json({
    success: true,
    data: {
      connectedClients: clients.size,
      status: 'healthy'
    }
  });
});

// Serve uploaded files
app.use('/api/uploads', express.static(path.join(__dirname, 'uploads')));

// ================== ADMIN ROUTES ==================

// Admin User Management
app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 50, search = '' } = req.query;
    const skip = (page - 1) * limit;
    
    const filter = search ? {
      $or: [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { name: { $regex: search, $options: 'i' } }
      ]
    } : {};
    
    const users = await User.find(filter)
      .select("-password -secretAnswer -confirmPassword")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await User.countDocuments(filter);
    
    res.json({
      success: true,
      data: {
        users,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get("/api/admin/users/:userId", adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select("-password -secretAnswer -confirmPassword");
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    res.json({ success: true, data: user });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put("/api/admin/users/:userId/block", adminAuth, async (req, res) => {
  try {
    const { isBlocked, reason } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.userId,
      { isBlocked },
      { new: true }
    ).select("-password -secretAnswer -confirmPassword");
    
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    
    if (isBlocked) {
      await sendNotification(
        user._id,
        "Account Blocked",
        `Your account has been blocked.${reason ? ` Reason: ${reason}` : ''}`,
        "security"
      );
    } else {
      await sendNotification(
        user._id,
        "Account Unblocked",
        "Your account has been unblocked. You can now access all features.",
        "security"
      );
    }
    
    res.json({ 
      success: true,
      message: `User ${isBlocked ? 'blocked' : 'unblocked'} successfully`, 
      data: { user } 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Admin Transaction Routes
app.get("/api/admin/transactions", adminAuth, async (req, res) => {
  try {
    const { type, status, page = 1, limit = 50 } = req.query;
    const skip = (page - 1) * limit;
    
    const filter = {};
    if (type) filter.type = type;
    if (status) filter.status = status;
    
    const transactions = await Transaction.find(filter)
      .populate("user", "name email username role")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(filter);
    
    res.json({
      success: true,
      data: {
        transactions,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Enhanced withdrawal approval/rejection routes with success/failure messages
app.put("/api/admin/withdrawal/:transactionId/approve", adminAuth, transactionController.approveWithdrawal);
app.put("/api/admin/withdrawal/:transactionId/reject", adminAuth, transactionController.rejectWithdrawal);
app.put("/api/admin/deposit/:transactionId/approve", adminAuth, transactionController.approveDeposit);
app.put("/api/admin/deposit/:transactionId/reject", adminAuth, transactionController.rejectDeposit);

// Investment Admin Routes
app.put("/api/admin/investment/:transactionId/approve", adminAuth, investmentController.approveInvestment);

app.put("/api/admin/investment/:transactionId/reject", adminAuth, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { adminNote } = req.body;
    
    const tx = await Transaction.findById(transactionId).populate('user');
    if (!tx || tx.type !== "investment") {
      return res.status(404).json({ 
        success: false,
        message: "Investment transaction not found" 
      });
    }
    
    if (tx.status === "rejected") {
      return res.status(400).json({ 
        success: false,
        message: "Investment already rejected" 
      });
    }

    tx.status = "rejected";
    if (adminNote) tx.adminNote = adminNote;
    await tx.save();

    await sendNotification(
      tx.user._id,
      "Investment Rejected ❌",
      `Your investment of $${tx.amount} in ${tx.investmentPlan} was rejected.${adminNote ? ` Reason: ${adminNote}` : ''}`,
      "investment",
      tx._id,
      "transaction"
    );

    res.json({ 
      success: true,
      message: "Investment rejected successfully", 
      data: { transaction: tx } 
    });
  } catch (error) { 
    console.error('Investment rejection error:', error);
    res.status(500).json({ 
      success: false,
      message: "Investment rejection failed" 
    }); 
  }
});

// Admin Message Routes
app.post("/api/admin/message", adminAuth, messageController.sendMessage);

// Admin Dashboard
app.get("/api/admin/dashboard-stats", adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalDeposits = await Transaction.aggregate([
      { $match: { type: "deposit", status: "approved" } },
      { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);
    const totalWithdrawals = await Transaction.aggregate([
      { $match: { type: "withdrawal", status: "approved" } },
      { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);
    const totalInvestments = await Transaction.aggregate([
      { $match: { type: "investment", status: "approved" } },
      { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);
    const pendingTransactions = await Transaction.countDocuments({ 
      status: "pending" 
    });
    
    const recentRegistrations = await User.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .select("username email location createdAt");
    
    res.json({
      success: true,
      data: {
        totalUsers,
        totalDeposits: totalDeposits[0]?.total || 0,
        totalWithdrawals: totalWithdrawals[0]?.total || 0,
        totalInvestments: totalInvestments[0]?.total || 0,
        pendingTransactions,
        recentRegistrations
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Balance Management
// app.put("/api/admin/user/:userId/balance", adminAuth, async (req, res) => {
//   try {
//     const { userId } = req.params;
//     const { walletBalance, depositBalance, note } = req.body;
    
//     const user = await User.findById(userId);
//     if (!user) return res.status(404).json({ success: false, message: "User not found" });
    
//     if (walletBalance !== undefined) user.walletBalance = Number(walletBalance);
//     if (depositBalance !== undefined) user.depositBalance = Number(depositBalance);
    
//     await user.save();
    
//     await sendNotification(
//       user._id,
//       "Balance Updated",
//       `Admin updated your balances.${note ? ` Note: ${note}` : ''}`,
//       "system"
//     );

//     sendUserUpdate(user._id.toString(), {
//       type: 'BALANCE_UPDATE',
//       walletBalance: user.walletBalance,
//       depositBalance: user.depositBalance,
//       message: 'Your balances have been updated by admin'
//     });

//     res.json({ 
//       success: true,
//       message: "Balances updated successfully", 
//       data: {
//         walletBalance: user.walletBalance, 
//         depositBalance: user.depositBalance 
//       } 
//     });
//   } catch (error) { 
//     res.status(500).json({ success: false, message: error.message }); 
//   }
// });



// ================== ENHANCED ADMIN CONTROLLERS ==================

// Enhanced Admin Balance Management with Real-time Updates
app.put("/api/admin/user/:userId/balance", adminAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const { walletBalance, depositBalance, totalInvested, note, type = "manual" } = req.body;
    
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    // Track changes for notification
    const changes = [];
    const oldWalletBalance = user.walletBalance;
    const oldDepositBalance = user.depositBalance;
    const oldTotalInvested = user.totalInvested;

    if (walletBalance !== undefined) {
      user.walletBalance = Number(walletBalance);
      changes.push(`Wallet: $${oldWalletBalance} → $${user.walletBalance}`);
    }
    
    if (depositBalance !== undefined) {
      user.depositBalance = Number(depositBalance);
      changes.push(`Deposit: $${oldDepositBalance} → $${user.depositBalance}`);
    }
    
    if (totalInvested !== undefined) {
      user.totalInvested = Number(totalInvested);
      changes.push(`Invested: $${oldTotalInvested} → $${user.totalInvested}`);
    }

    await user.save();

    // Create transaction record for audit trail
    const transaction = await Transaction.create({
      user: user._id,
      type: "admin_adjustment",
      amount: walletBalance !== undefined ? (user.walletBalance - oldWalletBalance) : 0,
      status: "approved",
      adminNote: `Admin manual adjustment: ${changes.join(', ')}. ${note || ''}`,
      processed: true
    });

    // Send real-time notification to user
    await sendNotification(
      user._id,
      "Account Balance Updated",
      `Admin has updated your account balances. Changes: ${changes.join(', ')}.${note ? ` Note: ${note}` : ''}`,
      "balance_update",
      transaction._id,
      "transaction"
    );

    // Real-time WebSocket update
    sendUserUpdate(user._id.toString(), {
      type: 'BALANCE_UPDATE',
      walletBalance: user.walletBalance,
      depositBalance: user.depositBalance,
      totalInvested: user.totalInvested,
      transaction: transaction,
      message: 'Your balances have been updated by admin',
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Balances updated successfully", 
      data: {
        user: {
          walletBalance: user.walletBalance, 
          depositBalance: user.depositBalance,
          totalInvested: user.totalInvested
        },
        changes: changes,
        transactionId: transaction._id
      } 
    });
  } catch (error) { 
    console.error('Balance update error:', error);
    res.status(500).json({ success: false, message: error.message }); 
  }
});

// Enhanced Profit Management with Real-time Updates
app.post("/api/admin/user/:userId/profit", adminAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const { amount, note, investmentId } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, message: "Valid profit amount is required" });
    }

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    const oldBalance = user.walletBalance;
    user.walletBalance += Number(amount);
    await user.save();

    // Create profit record
    const profit = await Profit.create({
      userId: user._id,
      amount: Number(amount),
      note: note || "Admin added profit",
      investmentId: investmentId || null
    });

    // Create transaction record
    const transaction = await Transaction.create({
      user: user._id,
      type: "profit",
      amount: Number(amount),
      status: "approved",
      adminNote: `Admin added profit: ${note || 'Manual profit addition'}`,
      processed: true
    });

    // Send notification
    await sendNotification(
      user._id,
      "Profit Added ✅",
      `$${amount} has been added to your wallet as profit.${note ? ` Note: ${note}` : ''}`,
      "profit",
      transaction._id,
      "transaction"
    );

    // Real-time update
    sendUserUpdate(user._id.toString(), {
      type: 'PROFIT_ADDED',
      walletBalance: user.walletBalance,
      profitAmount: Number(amount),
      transaction: transaction,
      profit: profit,
      message: `Profit of $${amount} has been added to your account`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Profit added successfully", 
      data: {
        user: {
          walletBalance: user.walletBalance,
          profitAdded: Number(amount)
        },
        profit: profit,
        transaction: transaction
      } 
    });
  } catch (error) {
    console.error('Profit addition error:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Enhanced Deposit Approval with Real-time Updates
app.put("/api/admin/deposit/:transactionId/approve", adminAuth, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { adminNote } = req.body;
    
    const tx = await Transaction.findById(transactionId).populate('user');
    if (!tx || tx.type !== "deposit") {
      return res.status(404).json({ 
        success: false,
        message: "Deposit transaction not found" 
      });
    }
    
    if (tx.status === "approved") {
      return res.status(400).json({ 
        success: false,
        message: "Deposit already approved" 
      });
    }

    const user = await User.findById(tx.user._id);
    const oldWalletBalance = user.walletBalance;
    const oldDepositBalance = user.depositBalance;

    // Add to both wallet and deposit balance
    user.walletBalance += tx.amount;
    user.depositBalance += tx.amount;
    await user.save();

    tx.status = "approved";
    tx.processed = true;
    if (adminNote) tx.adminNote = adminNote;
    await tx.save();

    // Send notification
    await sendNotification(
      tx.user._id,
      "Deposit Approved ✅",
      `Your deposit of $${tx.amount} has been approved and added to your balances.${adminNote ? ` Note: ${adminNote}` : ''}`,
      "deposit",
      tx._id,
      "transaction"
    );

    // Real-time update
    sendUserUpdate(tx.user._id.toString(), {
      type: 'DEPOSIT_APPROVED',
      walletBalance: user.walletBalance,
      depositBalance: user.depositBalance,
      transaction: tx,
      amount: tx.amount,
      message: `Deposit of $${tx.amount} has been approved and added to your balances`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Deposit approved successfully", 
      data: { 
        transaction: tx,
        userBalance: {
          walletBalance: user.walletBalance,
          depositBalance: user.depositBalance,
          increase: tx.amount
        }
      }
    });
  } catch (error) { 
    console.error('Deposit approval error:', error);
    res.status(500).json({ 
      success: false,
      message: "Deposit approval failed" 
    }); 
  }
});

// Enhanced Investment Approval with Profit Calculation
app.put("/api/admin/investment/:transactionId/approve", adminAuth, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const tx = await Transaction.findById(transactionId).populate('user');
    
    if (!tx || tx.type !== "investment") {
      return res.status(404).json({ 
        success: false,
        message: "Investment transaction not found" 
      });
    }
    
    if (tx.status === "approved") {
      return res.status(400).json({ 
        success: false,
        message: "Investment already approved" 
      });
    }

    const user = await User.findById(tx.user._id);
    
    if (user.depositBalance < tx.amount) {
      return res.status(400).json({ 
        success: false,
        message: "User has insufficient deposit balance" 
      });
    }

    const plans = {
      "Basic Plan": { profitRate: 5, duration: 30 },
      "Premium Plan": { profitRate: 8, duration: 30 },
      "VIP Plan": { profitRate: 12, duration: 30 }
    };

    const plan = plans[tx.investmentPlan];
    if (!plan) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid investment plan" 
      });
    }

    // Deduct from deposit balance, add to total invested
    user.depositBalance -= tx.amount;
    user.totalInvested += tx.amount;
    await user.save();

    tx.status = "approved";
    await tx.save();

    const expectedProfit = tx.amount * plan.profitRate / 100;
    const investment = await Investment.create({
      user: user._id,
      transaction: tx._id,
      planName: tx.investmentPlan,
      amount: tx.amount,
      profitRate: plan.profitRate,
      expectedProfit: expectedProfit,
      endDate: new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000)
    });

    // Send notification
    await sendNotification(
      user._id,
      "Investment Approved ✅",
      `Your investment of $${tx.amount} in ${tx.investmentPlan} has been approved. Expected profit: $${expectedProfit.toFixed(2)} over ${plan.duration} days.`,
      "investment",
      investment._id,
      "investment"
    );

    // Real-time update
    sendUserUpdate(user._id.toString(), {
      type: 'INVESTMENT_APPROVED',
      walletBalance: user.walletBalance,
      depositBalance: user.depositBalance,
      totalInvested: user.totalInvested,
      investment: investment,
      expectedProfit: expectedProfit,
      message: `Investment of $${tx.amount} in ${tx.investmentPlan} has been approved`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Investment approved successfully", 
      data: {
        transaction: tx,
        investment: investment,
        userBalance: {
          walletBalance: user.walletBalance,
          depositBalance: user.depositBalance,
          totalInvested: user.totalInvested
        },
        profitDetails: {
          expectedProfit: expectedProfit,
          profitRate: plan.profitRate,
          duration: plan.duration
        }
      }
    });
  } catch (error) { 
    console.error('Investment approval error:', error);
    res.status(500).json({ 
      success: false,
      message: "Investment approval failed" 
    }); 
  }
});

// ================== ENHANCED WEB SOCKET HANDLING ==================

function sendUserUpdate(userId, data) {
  const ws = clients.get(userId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify({
        ...data,
        timestamp: new Date().toISOString()
      }));
      console.log(`Real-time update sent to user ${userId}:`, data.type);
    } catch (error) {
      console.error('Error sending WebSocket message:', error);
      // Remove disconnected client
      clients.delete(userId);
    }
  } else {
    console.log(`User ${userId} not connected via WebSocket. Update will be seen on next login.`);
  }
}



// ================== ENHANCED FRONTEND DASHBOARD UPDATES ==================

// Add this to your frontend JavaScript to handle real-time updates
function setupWebSocket() {
  const token = localStorage.getItem('authToken');
  if (!token) return;

  const ws = new WebSocket(`ws://${window.location.host}/ws`);
  
  ws.onopen = () => {
    console.log('WebSocket connected');
    ws.send(JSON.stringify({ type: 'AUTH', token: token }));
  };
  
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      console.log('WebSocket message received:', data);
      
      switch (data.type) {
        case 'CONNECTED':
          console.log('WebSocket authenticated successfully');
          break;
          
        case 'BALANCE_UPDATE':
          updateUserBalances(data);
          showNotification('success', data.message || 'Balance updated');
          break;
          
        case 'DEPOSIT_APPROVED':
          updateUserBalances(data);
          showNotification('success', data.message || 'Deposit approved');
          loadTransactions(); // Refresh transactions list
          break;
          
        case 'WITHDRAWAL_APPROVED':
          updateUserBalances(data);
          showNotification('success', data.message || 'Withdrawal approved');
          loadTransactions();
          break;
          
        case 'WITHDRAWAL_REJECTED':
          updateUserBalances(data);
          showNotification('warning', data.message || 'Withdrawal rejected');
          loadTransactions();
          break;
          
        case 'INVESTMENT_APPROVED':
          updateUserBalances(data);
          showNotification('success', data.message || 'Investment approved');
          loadActiveInvestments();
          break;
          
        case 'PROFIT_ADDED':
          updateUserBalances(data);
          showNotification('success', data.message || 'Profit added');
          break;
          
        case 'NEW_NOTIFICATION':
          showNotification('info', data.message);
          loadUserNotifications();
          updateNotificationBadge();
          break;
          
        case 'NEW_MESSAGE':
          showNotification('info', 'You have a new message');
          break;
          
        case 'ERROR':
          showNotification('error', data.message);
          break;
      }
    } catch (error) {
      console.error('Error processing WebSocket message:', error);
    }
  };
  
  ws.onclose = () => {
    console.log('WebSocket disconnected');
    // Attempt to reconnect after 5 seconds
    setTimeout(setupWebSocket, 5000);
  };
  
  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
  };
}

function updateUserBalances(data) {
  if (data.walletBalance !== undefined) {
    document.getElementById('walletBalance').textContent = data.walletBalance.toFixed(2);
  }
  if (data.depositBalance !== undefined) {
    document.getElementById('depositBalance').textContent = data.depositBalance.toFixed(2);
  }
  if (data.totalInvested !== undefined) {
    document.getElementById('totalInvested').textContent = data.totalInvested.toFixed(2);
  }
  if (data.availableBalance !== undefined) {
    document.getElementById('availableBalance').textContent = data.availableBalance.toFixed(2);
  }
}

function showNotification(type, message) {
  // Create notification element
  const notification = document.createElement('div');
  notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
  notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
  notification.innerHTML = `
    ${message}
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
  `;
  
  document.body.appendChild(notification);
  
  // Auto remove after 5 seconds
  setTimeout(() => {
    if (notification.parentNode) {
      notification.remove();
    }
  }, 5000);
}

// Initialize WebSocket when page loads
document.addEventListener('DOMContentLoaded', function() {
  if (localStorage.getItem('authToken')) {
    setupWebSocket();
  }
});

// ================== ENHANCED ADMIN DASHBOARD FUNCTIONS ==================

// Admin function to manually add profit to user
async function addUserProfit(userId, amount, note = '') {
  try {
    const response = await fetch(`/api/admin/user/${userId}/profit`, {
      method: 'POST',
      headers: {
        'Admin-Username': ADMIN_CREDENTIALS.username,
        'Admin-Password': ADMIN_CREDENTIALS.password,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ amount, note })
    });
    
    const result = await response.json();
    
    if (result.success) {
      showAdminNotification('success', `Profit of $${amount} added to user successfully`);
      loadAdminUsers(); // Refresh user list
      return result.data;
    } else {
      showAdminNotification('error', result.message);
      return null;
    }
  } catch (error) {
    console.error('Error adding profit:', error);
    showAdminNotification('error', 'Failed to add profit');
    return null;
  }
}

// Admin function to update user balances
async function updateUserBalancesAdmin(userId, walletBalance, depositBalance, totalInvested, note = '') {
  try {
    const response = await fetch(`/api/admin/user/${userId}/balance`, {
      method: 'PUT',
      headers: {
        'Admin-Username': ADMIN_CREDENTIALS.username,
        'Admin-Password': ADMIN_CREDENTIALS.password,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ walletBalance, depositBalance, totalInvested, note })
    });
    
    const result = await response.json();
    
    if (result.success) {
      showAdminNotification('success', 'User balances updated successfully');
      loadAdminUsers(); // Refresh user list
      return result.data;
    } else {
      showAdminNotification('error', result.message);
      return null;
    }
  } catch (error) {
    console.error('Error updating balances:', error);
    showAdminNotification('error', 'Failed to update balances');
    return null;
  }
}

// Enhanced admin notification system
function showAdminNotification(type, message) {
  const notification = document.createElement('div');
  notification.className = `alert alert-${type} alert-dismissible fade show`;
  notification.innerHTML = `
    ${message}
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
  `;
  
  // Add to admin dashboard
  const adminContainer = document.querySelector('.admin-dashboard .container') || document.body;
  adminContainer.insertBefore(notification, adminContainer.firstChild);
  
  setTimeout(() => {
    if (notification.parentNode) {
      notification.remove();
    }
  }, 5000);
}







// Serve frontend last, only for non-API routes
app.use(express.static(path.join(__dirname, "public")));
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ================== ERROR HANDLING ==================
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: 'File too large. Maximum size is 5MB.'
      });
    }
  }
  
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { error: error.message })
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`
  });
});

// ================== START SERVER ==================
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 WebSocket server available at ws://localhost:${PORT}/ws`);
  console.log(`🔑 Admin credentials: ${ADMIN_USERNAME}/${ADMIN_PASSWORD}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
  });
});