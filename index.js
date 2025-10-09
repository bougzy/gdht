// ================== IMPORTS ==================
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const path = require("path");
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




app.use(requestIp.mw());
const server = http.createServer(app);

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// ================== DB CONNECTION ==================
mongoose.connect(process.env.MONGO_URI || "mongodb+srv://trader:trader@trader.wuudnoj.mongodb.net/trader", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("✅ MongoDB connected successfully"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// ================== ENHANCED LOCATION UTILITIES ==================

const validateAndCleanIP = (ip) => {
  if (!ip) return '0.0.0.0';
  if (ip === '::1') return '127.0.0.1';
  if (ip.includes(':')) {
    const parts = ip.split(':');
    const possibleIp = parts[parts.length - 1];
    if (possibleIp && possibleIp !== '') return possibleIp;
  }
  return ip;
};

const getUserLocation = (ip) => {
  const cleanIp = validateAndCleanIP(ip);
  
  if (cleanIp === '127.0.0.1') {
    return {
      country: 'US',
      countryCode: 'US',
      region: 'California',
      regionName: 'California',
      city: 'San Francisco',
      zip: '94107',
      lat: 37.7749,
      lon: -122.4194,
      timezone: 'America/Los_Angeles',
      isp: 'Local Development',
      org: 'Local Network',
      as: 'AS0 Local',
      query: cleanIp,
      source: 'fallback'
    };
  }

  try {
    const geo = geoip.lookup(cleanIp);
    if (geo) {
      return {
        country: geo.country,
        countryCode: geo.country,
        region: geo.region,
        regionName: geo.region,
        city: geo.city,
        zip: '',
        lat: geo.ll[0],
        lon: geo.ll[1],
        timezone: geo.timezone,
        isp: 'Unknown',
        org: 'Unknown',
        as: 'Unknown',
        query: cleanIp,
        source: 'geoip-lite'
      };
    }
  } catch (error) {
    console.error('❌ Error in location lookup:', error);
  }

  return {
    country: 'Unknown',
    countryCode: 'XX',
    region: 'Unknown',
    regionName: 'Unknown',
    city: 'Unknown',
    zip: '',
    lat: 0,
    lon: 0,
    timezone: 'UTC',
    isp: 'Unknown',
    org: 'Unknown',
    as: 'Unknown',
    query: cleanIp,
    source: 'fallback'
  };
};

// ================== MODELS ==================

// Enhanced User Schema with Better Location Tracking
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
    countryCode: String,
    region: String,
    regionName: String,
    city: String,
    zip: String,
    timezone: String,
    coordinates: {
      latitude: Number,
      longitude: Number
    },
    isp: String,
    organization: String,
    asNumber: String,
    source: String,
    queryIp: String,
    lastUpdated: Date
  },
  lastLogin: { type: Date },
  loginHistory: [{
    ip: String,
    location: Object,
    timestamp: { type: Date, default: Date.now },
    event: String
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
  type: { type: String, enum: ["deposit", "withdrawal", "investment", "profit", "admin_adjustment"], required: true },
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
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || 
        file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDF files are allowed'), false);
    }
  }
});

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

// Enhanced user location update middleware
const updateUserLocation = async (req, res, next) => {
  if (req.user) {
    try {
      const rawIp = req.clientIp;
      const cleanedIp = validateAndCleanIP(rawIp);
      const locationData = getUserLocation(cleanedIp);

      if (locationData.country && locationData.country !== 'Unknown') {
        await User.findByIdAndUpdate(req.user._id, {
          $set: {
            ipAddress: cleanedIp,
            lastLogin: new Date(),
            'location.country': locationData.country,
            'location.city': locationData.city,
            'location.coordinates.latitude': locationData.lat,
            'location.coordinates.longitude': locationData.lon,
            'location.timezone': locationData.timezone,
            'location.lastUpdated': new Date()
          },
          $push: {
            loginHistory: {
              ip: cleanedIp,
              location: locationData,
              timestamp: new Date(),
              event: 'login'
            }
          }
        });
      }
    } catch (error) {
      console.error('Error updating user location:', error);
    }
  }
  next();
};

// ================== UTILS ==================
const generateToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET || "supersecretjwtkey", { expiresIn: "7d" });
};

// Enhanced WebSocket system
const wss = new WebSocket.Server({ 
  server,
  path: '/ws',
  perMessageDeflate: false
});

const clients = new Map();

wss.on('connection', (ws, req) => {
  console.log('🔌 New WebSocket connection attempt');
  
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
          
          console.log(`✅ User ${userId} connected via WebSocket`);
          
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
      console.log(`❌ User ${ws.userId} disconnected from WebSocket`);
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

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER || 'your_email@gmail.com',
    pass: process.env.SMTP_PASS || 'your_password'
  }
});

// ================== ENHANCED AUTH ROUTES ==================

// Enhanced Registration with Complete Location Tracking
app.post("/api/register", async (req, res) => {
  try {
    const {
      username, name, email, password, confirmPassword,
      bitcoinAccount, tetherTRC20Account, secretQuestion,
      secretAnswer, agreedToTerms, referralCode
    } = req.body;

    console.log('🚀 Registration attempt started for:', { email, username });

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

    // Enhanced location tracking
    const rawIp = req.clientIp;
    const cleanedIp = validateAndCleanIP(rawIp);
    const locationData = getUserLocation(cleanedIp);

    console.log('📍 User location data:', {
      ip: cleanedIp,
      country: locationData.country,
      city: locationData.city,
      source: locationData.source
    });

    const existingUser = await User.findOne({ 
      $or: [
        { email: email.toLowerCase().trim() }, 
        { username: username.toLowerCase().trim() }
      ] 
    });
    
    if (existingUser) {
      if (existingUser.email === email.toLowerCase().trim()) {
        return res.status(400).json({ 
          success: false,
          message: "Email already registered" 
        });
      }
      if (existingUser.username === username.toLowerCase().trim()) {
        return res.status(400).json({ 
          success: false,
          message: "Username already taken" 
        });
      }
    }

    let referredBy = null;
    if (referralCode && referralCode.trim() !== '') {
      const referrer = await User.findOne({ 
        referralCode: referralCode.toUpperCase().trim() 
      });
      if (referrer) referredBy = referrer._id;
    }

    const userData = {
      username: username.toLowerCase().trim(),
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: password,
      confirmPassword: confirmPassword,
      bitcoinAccount: bitcoinAccount ? bitcoinAccount.trim() : undefined,
      tetherTRC20Account: tetherTRC20Account ? tetherTRC20Account.trim() : undefined,
      secretQuestion: secretQuestion.trim(),
      secretAnswer: secretAnswer.trim(),
      agreedToTerms: !!agreedToTerms,
      referredBy: referredBy,
      ipAddress: cleanedIp,
      location: {
        country: locationData.country,
        countryCode: locationData.countryCode,
        region: locationData.region,
        regionName: locationData.regionName,
        city: locationData.city,
        zip: locationData.zip,
        timezone: locationData.timezone,
        coordinates: {
          latitude: locationData.lat,
          longitude: locationData.lon
        },
        isp: locationData.isp,
        organization: locationData.org,
        asNumber: locationData.as,
        source: locationData.source,
        queryIp: locationData.query,
        lastUpdated: new Date()
      },
      loginHistory: [{
        ip: cleanedIp,
        location: locationData,
        timestamp: new Date(),
        event: 'registration'
      }]
    };

    const user = await User.create(userData);

    if (referredBy) {
      await User.findByIdAndUpdate(referredBy, { 
        $push: { referrals: user._id } 
      });
    }

    await sendNotification(
      user._id,
      "🎉 Welcome to Our Platform!",
      `Thank you for registering, ${user.name}! Your account has been created successfully. ` +
      `You registered from ${locationData.city || 'Unknown'}, ${locationData.country || 'Unknown'}.`,
      "welcome"
    );

    const userResponse = await User.findById(user._id)
      .select("-password -secretAnswer -confirmPassword -loginHistory");

    res.status(201).json({
      success: true,
      data: {
        user: userResponse,
        token: generateToken(user._id, user.role),
        location: {
          country: locationData.country,
          city: locationData.city,
          timezone: locationData.timezone
        }
      },
      message: `Registration successful! Welcome, ${user.name}!`
    });

  } catch (error) {
    console.error('💥 Registration error:', error);
    
    if (error.code === 11000) {
      const field = Object.keys(error.keyValue)[0];
      return res.status(400).json({ 
        success: false,
        message: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists` 
      });
    }
    
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(val => val.message);
      return res.status(400).json({ 
        success: false,
        message: messages.join(', ') 
      });
    }

    res.status(500).json({ 
      success: false,
      message: "Registration failed. Please try again." 
    });
  }
});

app.post("/api/login", async (req, res) => {
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
      
      const rawIp = req.clientIp;
      const cleanedIp = validateAndCleanIP(rawIp);
      const locationData = getUserLocation(cleanedIp);

      await User.findByIdAndUpdate(user._id, {
        $set: {
          ipAddress: cleanedIp,
          lastLogin: new Date(),
          ...(locationData.country !== 'Unknown' && {
            'location.country': locationData.country,
            'location.city': locationData.city,
            'location.coordinates.latitude': locationData.lat,
            'location.coordinates.longitude': locationData.lon,
            'location.lastUpdated': new Date()
          })
        },
        $push: {
          loginHistory: {
            ip: cleanedIp,
            location: locationData,
            timestamp: new Date(),
            event: 'login'
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
});

// ================== ENHANCED ADMIN ROUTES ==================

// Admin Dashboard with Complete Statistics
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
    
    const pendingDeposits = await Transaction.countDocuments({ 
      type: "deposit", 
      status: "pending" 
    });
    
    const pendingWithdrawals = await Transaction.countDocuments({ 
      type: "withdrawal", 
      status: "pending" 
    });
    
    const recentRegistrations = await User.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .select("username email location ipAddress createdAt");

    // Location statistics
    const usersWithLocation = await User.find({ 'location.country': { $ne: 'Unknown' } });
    const countryStats = {};
    usersWithLocation.forEach(user => {
      const country = user.location.country;
      countryStats[country] = (countryStats[country] || 0) + 1;
    });

    res.json({
      success: true,
      data: {
        totalUsers,
        totalDeposits: totalDeposits[0]?.total || 0,
        totalWithdrawals: totalWithdrawals[0]?.total || 0,
        totalInvestments: totalInvestments[0]?.total || 0,
        pendingTransactions: {
          deposits: pendingDeposits,
          withdrawals: pendingWithdrawals,
          total: pendingDeposits + pendingWithdrawals
        },
        recentRegistrations,
        locationStats: {
          totalWithLocation: usersWithLocation.length,
          countries: countryStats
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Enhanced Admin Transactions with Location Data
app.get("/api/admin/transactions", adminAuth, async (req, res) => {
  try {
    const { type, status, page = 1, limit = 50 } = req.query;
    
    const filter = {};
    if (type && type !== 'all') filter.type = type;
    if (status && status !== 'all') filter.status = status;
    
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find(filter)
      .populate('user', 'username email location ipAddress')
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

// Get Pending Deposits Specifically
app.get("/api/admin/pending-deposits", adminAuth, async (req, res) => {
  try {
    const pendingDeposits = await Transaction.find({ 
      type: "deposit", 
      status: "pending" 
    })
    .populate('user', 'username email location ipAddress createdAt')
    .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      message: "Pending deposits retrieved successfully",
      data: {
        deposits: pendingDeposits,
        count: pendingDeposits.length
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Enhanced Deposit Approval with Real-time Updates
app.put("/api/admin/deposit/:transactionId/approve", adminAuth, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { adminNote } = req.body;
    
    const transaction = await Transaction.findById(transactionId).populate('user');
    if (!transaction || transaction.type !== "deposit") {
      return res.status(404).json({ 
        success: false,
        message: "Deposit transaction not found" 
      });
    }
    
    if (transaction.status === "approved") {
      return res.status(400).json({ 
        success: false,
        message: "Deposit already approved" 
      });
    }

    const user = await User.findById(transaction.user._id);
    const oldWalletBalance = user.walletBalance;
    const oldDepositBalance = user.depositBalance;

    // Add to both wallet and deposit balance
    user.walletBalance += transaction.amount;
    user.depositBalance += transaction.amount;
    await user.save();

    transaction.status = "approved";
    transaction.processed = true;
    if (adminNote) transaction.adminNote = adminNote;
    await transaction.save();

    // Send notification to user
    await sendNotification(
      transaction.user._id,
      "Deposit Approved ✅",
      `Your deposit of $${transaction.amount} has been approved and added to your balances.`,
      "deposit",
      transaction._id,
      "transaction"
    );

    // Real-time update via WebSocket
    sendUserUpdate(transaction.user._id.toString(), {
      type: 'DEPOSIT_APPROVED',
      walletBalance: user.walletBalance,
      depositBalance: user.depositBalance,
      transaction: transaction,
      amount: transaction.amount,
      message: `Deposit of $${transaction.amount} has been approved and added to your balances`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Deposit approved successfully", 
      data: { 
        transaction: transaction,
        userBalance: {
          walletBalance: user.walletBalance,
          depositBalance: user.depositBalance,
          increase: transaction.amount
        },
        userLocation: user.location
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

// Enhanced Admin User Management
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

// ================== ENHANCED INVESTMENT APPROVAL ROUTES ==================

// Get pending investments for admin
app.get("/api/admin/pending-investments", adminAuth, async (req, res) => {
  try {
    const pendingInvestments = await Transaction.find({ 
      type: "investment", 
      status: "pending" 
    })
    .populate('user', 'username email location ipAddress createdAt')
    .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      message: "Pending investments retrieved successfully",
      data: {
        investments: pendingInvestments,
        count: pendingInvestments.length
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Approve investment
app.put("/api/admin/investment/:transactionId/approve", adminAuth, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { adminNote } = req.body;
    
    const transaction = await Transaction.findById(transactionId).populate('user');
    if (!transaction || transaction.type !== "investment") {
      return res.status(404).json({ 
        success: false,
        message: "Investment transaction not found" 
      });
    }
    
    if (transaction.status === "approved") {
      return res.status(400).json({ 
        success: false,
        message: "Investment already approved" 
      });
    }

    const user = await User.findById(transaction.user._id);
    
    if (user.depositBalance < transaction.amount) {
      return res.status(400).json({ 
        success: false,
        message: "User has insufficient deposit balance for this investment" 
      });
    }

    // Deduct from deposit balance and add to total invested
    user.depositBalance -= transaction.amount;
    user.totalInvested += transaction.amount;
    await user.save();

    // Create investment record
    const plans = [
      { id: "1", name: "Basic Plan", profitRate: 5 },
      { id: "2", name: "Premium Plan", profitRate: 8 },
      { id: "3", name: "VIP Plan", profitRate: 12 }
    ];
    
    const plan = plans.find(p => p.id === transaction.investmentPlan) || 
                plans.find(p => p.name === transaction.investmentPlan) ||
                plans[0];

    const investment = await Investment.create({
      user: user._id,
      transaction: transaction._id,
      planName: plan.name,
      amount: transaction.amount,
      profitRate: plan.profitRate,
      expectedProfit: transaction.amount * (plan.profitRate / 100),
      startDate: new Date(),
      endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      status: "active"
    });

    transaction.status = "approved";
    transaction.processed = true;
    if (adminNote) transaction.adminNote = adminNote;
    await transaction.save();

    // Send notification to user
    await sendNotification(
      transaction.user._id,
      "Investment Approved ✅",
      `Your investment of $${transaction.amount} in ${plan.name} has been approved and activated. Expected profit: $${investment.expectedProfit.toFixed(2)}.`,
      "investment",
      transaction._id,
      "transaction"
    );

    // Real-time update via WebSocket
    sendUserUpdate(transaction.user._id.toString(), {
      type: 'INVESTMENT_APPROVED',
      walletBalance: user.walletBalance,
      depositBalance: user.depositBalance,
      totalInvested: user.totalInvested,
      transaction: transaction,
      investment: investment,
      amount: transaction.amount,
      message: `Your investment of $${transaction.amount} has been approved`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Investment approved successfully", 
      data: { 
        transaction: transaction,
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
});

// Reject investment
app.put("/api/admin/investment/:transactionId/reject", adminAuth, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { adminNote } = req.body;
    
    const transaction = await Transaction.findById(transactionId).populate('user');
    if (!transaction || transaction.type !== "investment") {
      return res.status(404).json({ 
        success: false,
        message: "Investment transaction not found" 
      });
    }
    
    transaction.status = "rejected";
    transaction.processed = true;
    if (adminNote) transaction.adminNote = adminNote;
    await transaction.save();

    // Send notification to user
    await sendNotification(
      transaction.user._id,
      "Investment Rejected ❌",
      `Your investment request of $${transaction.amount} has been rejected. ${adminNote ? `Reason: ${adminNote}` : ''}`,
      "investment",
      transaction._id,
      "transaction"
    );

    // Real-time update via WebSocket
    sendUserUpdate(transaction.user._id.toString(), {
      type: 'INVESTMENT_REJECTED',
      transaction: transaction,
      amount: transaction.amount,
      message: `Your investment request of $${transaction.amount} has been rejected`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Investment rejected successfully", 
      data: { transaction }
    });
  } catch (error) { 
    console.error('Investment rejection error:', error);
    res.status(500).json({ 
      success: false,
      message: "Investment rejection failed" 
    }); 
  }
});

// ================== MANUAL TOP-UP ROUTES ==================

// Manual deposit top-up
app.post("/api/admin/user/:userId/topup-deposit", adminAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const { amount, note } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ 
        success: false,
        message: "Valid amount is required" 
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });
    }

    const oldDepositBalance = user.depositBalance;
    user.depositBalance += parseFloat(amount);
    await user.save();

    // Create transaction record
    const transaction = await Transaction.create({
      user: user._id,
      type: "admin_adjustment",
      amount: parseFloat(amount),
      status: "approved",
      adminNote: `Admin manual deposit top-up: $${amount}. ${note || ''}`,
      processed: true
    });

    // Send notification to user
    await sendNotification(
      user._id,
      "Deposit Top-Up Added ✅",
      `Admin has added $${amount} to your deposit balance. ${note || ''}`,
      "deposit",
      transaction._id,
      "transaction"
    );

    // Real-time update via WebSocket
    sendUserUpdate(user._id.toString(), {
      type: 'DEPOSIT_TOPUP',
      walletBalance: user.walletBalance,
      depositBalance: user.depositBalance,
      amount: amount,
      transaction: transaction,
      message: `$${amount} has been added to your deposit balance`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Deposit top-up successful", 
      data: {
        user: {
          depositBalance: user.depositBalance,
          previousBalance: oldDepositBalance
        },
        transaction: transaction
      }
    });
  } catch (error) {
    console.error('Deposit top-up error:', error);
    res.status(500).json({ 
      success: false,
      message: "Deposit top-up failed" 
    });
  }
});

// Manual investment top-up
app.post("/api/admin/user/:userId/topup-investment", adminAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const { amount, planId, note } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ 
        success: false,
        message: "Valid amount is required" 
      });
    }

    if (!planId) {
      return res.status(400).json({ 
        success: false,
        message: "Investment plan is required" 
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });
    }

    const plans = [
      { id: "1", name: "Basic Plan", profitRate: 5 },
      { id: "2", name: "Premium Plan", profitRate: 8 },
      { id: "3", name: "VIP Plan", profitRate: 12 }
    ];
    
    const plan = plans.find(p => p.id === planId);
    if (!plan) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid investment plan" 
      });
    }

    // Create investment directly without deducting from deposit balance
    const investment = await Investment.create({
      user: user._id,
      planName: plan.name,
      amount: parseFloat(amount),
      profitRate: plan.profitRate,
      expectedProfit: parseFloat(amount) * (plan.profitRate / 100),
      startDate: new Date(),
      endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      status: "active"
    });

    // Update user's total invested
    user.totalInvested += parseFloat(amount);
    await user.save();

    // Create transaction record
    const transaction = await Transaction.create({
      user: user._id,
      type: "investment",
      amount: parseFloat(amount),
      status: "approved",
      investmentPlan: plan.name,
      adminNote: `Admin manual investment top-up: $${amount} in ${plan.name}. ${note || ''}`,
      processed: true
    });

    // Link transaction to investment
    investment.transaction = transaction._id;
    await investment.save();

    // Send notification to user
    await sendNotification(
      user._id,
      "Investment Top-Up Added ✅",
      `Admin has added a new investment of $${amount} in ${plan.name} to your account. ${note || ''}`,
      "investment",
      transaction._id,
      "transaction"
    );

    // Real-time update via WebSocket
    sendUserUpdate(user._id.toString(), {
      type: 'INVESTMENT_TOPUP',
      walletBalance: user.walletBalance,
      depositBalance: user.depositBalance,
      totalInvested: user.totalInvested,
      amount: amount,
      investment: investment,
      transaction: transaction,
      message: `New investment of $${amount} in ${plan.name} has been added to your account`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Investment top-up successful", 
      data: {
        user: {
          totalInvested: user.totalInvested
        },
        investment: investment,
        transaction: transaction
      }
    });
  } catch (error) {
    console.error('Investment top-up error:', error);
    res.status(500).json({ 
      success: false,
      message: "Investment top-up failed" 
    });
  }
});

// Enhanced Admin Balance Management
app.put("/api/admin/user/:userId/balance", adminAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const { walletBalance, depositBalance, totalInvested, note } = req.body;
    
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ 
      success: false,
      message: "User not found" 
    });

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

    const transaction = await Transaction.create({
      user: user._id,
      type: "admin_adjustment",
      amount: walletBalance !== undefined ? (user.walletBalance - oldWalletBalance) : 0,
      status: "approved",
      adminNote: `Admin manual adjustment: ${changes.join(', ')}. ${note || ''}`,
      processed: true
    });

    await sendNotification(
      user._id,
      "Account Balance Updated",
      `Admin has updated your account balances. Changes: ${changes.join(', ')}.${note ? ` Note: ${note}` : ''}`,
      "balance_update",
      transaction._id,
      "transaction"
    );

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

// ================== USER ROUTES ==================

// User Profile Routes
app.put("/api/user/profile", protect, updateUserLocation, async (req, res) => {
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
});

// Get current user data - FIX FOR DASHBOARD
app.get("/api/me", protect, updateUserLocation, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select("-password -secretAnswer -confirmPassword");
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });
    }

    res.json({
      success: true,
      data: {
        user: {
          _id: user._id,
          username: user.username,
          name: user.name,
          email: user.email,
          walletBalance: user.walletBalance,
          depositBalance: user.depositBalance,
          totalInvested: user.totalInvested,
          bitcoinAccount: user.bitcoinAccount,
          tetherTRC20Account: user.tetherTRC20Account,
          secretQuestion: user.secretQuestion,
          referralCode: user.referralCode,
          location: user.location,
          createdAt: user.createdAt
        }
      },
      message: "User data retrieved successfully"
    });
  } catch (error) {
    console.error('Get user data error:', error);
    res.status(500).json({ 
      success: false,
      message: "Failed to fetch user data" 
    });
  }
});

// Deposit Routes
app.post("/api/deposits", protect, updateUserLocation, upload.single('proof'), async (req, res) => {
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
});

// Investment Routes
app.post("/api/investments", protect, updateUserLocation, async (req, res) => {
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


// Get user transactions
app.get("/api/user/transactions", protect, updateUserLocation, async (req, res) => {
  try {
    const { type } = req.query;
    const filter = { user: req.user._id };
    if (type && type !== 'all') filter.type = type;
    
    const transactions = await Transaction.find(filter)
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json({
      success: true,
      data: transactions,
      message: "Transactions retrieved successfully"
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get user referrals
app.get("/api/user/referrals", protect, updateUserLocation, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('referrals', 'username email createdAt totalInvested');
    
    res.json({
      success: true,
      data: {
        totalReferrals: user.referrals.length,
        referralCode: user.referralCode,
        referrals: user.referrals
      },
      message: "Referrals retrieved successfully"
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get user investments
app.get("/api/user/investments", protect, updateUserLocation, async (req, res) => {
  try {
    const investments = await Investment.find({ user: req.user._id })
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      data: investments,
      message: "Investments retrieved successfully"
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get user notifications
app.get("/api/user/notifications", protect, updateUserLocation, async (req, res) => {
  try {
    const notifications = await Notification.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50);
    
    const unreadCount = await Notification.countDocuments({ 
      user: req.user._id, 
      isRead: false 
    });
    
    res.json({
      success: true,
      data: {
        notifications,
        unreadCount
      },
      message: "Notifications retrieved successfully"
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Check approved deposits
app.get("/api/user/check-approved-deposits", protect, updateUserLocation, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.json({
      success: true,
      data: {
        walletBalance: user.walletBalance,
        depositBalance: user.depositBalance,
        processedCount: 0 // You can implement actual logic here
      },
      message: "No new approved deposits found"
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ================== ADDITIONAL ROUTES ==================

// Get user's location data
app.get("/api/user/location", protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('location ipAddress loginHistory');
    res.json({
      success: true,
      data: {
        location: user.location,
        ipAddress: user.ipAddress,
        loginCount: user.loginHistory.length
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Admin route to get all users with location data
app.get("/api/admin/users/locations", adminAuth, async (req, res) => {
  try {
    const users = await User.find()
      .select('username email location ipAddress createdAt lastLogin')
      .sort({ createdAt: -1 });
    
    const locationStats = {
      totalUsers: users.length,
      usersWithLocation: users.filter(u => u.location && u.location.country !== 'Unknown').length,
      countries: {},
      cities: {}
    };

    users.forEach(user => {
      if (user.location && user.location.country) {
        locationStats.countries[user.location.country] = 
          (locationStats.countries[user.location.country] || 0) + 1;
        
        if (user.location.city) {
          const cityKey = `${user.location.city}, ${user.location.country}`;
          locationStats.cities[cityKey] = (locationStats.cities[cityKey] || 0) + 1;
        }
      }
    });

    res.json({
      success: true,
      data: {
        users: users,
        statistics: locationStats
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Serve uploaded files
app.use('/api/uploads', express.static(path.join(__dirname, 'uploads')));

// Serve frontend last, only for non-API routes
app.use(express.static(path.join(__dirname, "public")));
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});


// ================== ENHANCED ADMIN ROUTES FOR COMPLETE SYNC ==================

// Enhanced Admin Dashboard with Real-time User Management
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
    
    const pendingDeposits = await Transaction.countDocuments({ 
      type: "deposit", 
      status: "pending" 
    });
    
    const pendingWithdrawals = await Transaction.countDocuments({ 
      type: "withdrawal", 
      status: "pending" 
    });
    
    const pendingInvestments = await Transaction.countDocuments({ 
      type: "investment", 
      status: "pending" 
    });

    const recentRegistrations = await User.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .select("username email location ipAddress createdAt");

    // Online users count (users with active WebSocket connections)
    const onlineUsers = Array.from(clients.keys()).length;

    res.json({
      success: true,
      data: {
        totalUsers,
        totalDeposits: totalDeposits[0]?.total || 0,
        totalWithdrawals: totalWithdrawals[0]?.total || 0,
        totalInvestments: totalInvestments[0]?.total || 0,
        pendingTransactions: {
          deposits: pendingDeposits,
          withdrawals: pendingWithdrawals,
          investments: pendingInvestments,
          total: pendingDeposits + pendingWithdrawals + pendingInvestments
        },
        recentRegistrations,
        onlineUsers,
        systemHealth: {
          database: 'connected',
          websocket: 'active',
          uptime: process.uptime()
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Enhanced Deposit Approval with Complete Sync
app.put("/api/admin/deposit/:transactionId/approve", adminAuth, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { adminNote } = req.body;
    
    const transaction = await Transaction.findById(transactionId).populate('user');
    if (!transaction || transaction.type !== "deposit") {
      return res.status(404).json({ 
        success: false,
        message: "Deposit transaction not found" 
      });
    }
    
    if (transaction.status === "approved") {
      return res.status(400).json({ 
        success: false,
        message: "Deposit already approved" 
      });
    }

    const user = await User.findById(transaction.user._id);
    const oldWalletBalance = user.walletBalance;
    const oldDepositBalance = user.depositBalance;

    // Add to both wallet and deposit balance
    user.walletBalance += transaction.amount;
    user.depositBalance += transaction.amount;
    await user.save();

    transaction.status = "approved";
    transaction.processed = true;
    if (adminNote) transaction.adminNote = adminNote;
    await transaction.save();

    // Send notification to user
    await sendNotification(
      transaction.user._id,
      "Deposit Approved ✅",
      `Your deposit of $${transaction.amount} has been approved and added to your balances.`,
      "deposit",
      transaction._id,
      "transaction"
    );

    // Real-time update via WebSocket
    sendUserUpdate(transaction.user._id.toString(), {
      type: 'DEPOSIT_APPROVED',
      walletBalance: user.walletBalance,
      depositBalance: user.depositBalance,
      transaction: transaction,
      amount: transaction.amount,
      message: `Deposit of $${transaction.amount} has been approved and added to your balances`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Deposit approved successfully", 
      data: { 
        transaction: transaction,
        userBalance: {
          walletBalance: user.walletBalance,
          depositBalance: user.depositBalance,
          increase: transaction.amount
        },
        userLocation: user.location
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

// Enhanced Withdrawal Management
app.put("/api/admin/withdrawal/:transactionId/approve", adminAuth, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { adminNote } = req.body;
    
    const transaction = await Transaction.findById(transactionId).populate('user');
    if (!transaction || transaction.type !== "withdrawal") {
      return res.status(404).json({ 
        success: false,
        message: "Withdrawal transaction not found" 
      });
    }
    
    if (transaction.status === "approved") {
      return res.status(400).json({ 
        success: false,
        message: "Withdrawal already approved" 
      });
    }

    const user = await User.findById(transaction.user._id);
    
    if (user.walletBalance < transaction.amount) {
      return res.status(400).json({ 
        success: false,
        message: "User has insufficient balance for this withdrawal" 
      });
    }

    // Deduct from wallet balance
    user.walletBalance -= transaction.amount;
    await user.save();

    transaction.status = "approved";
    transaction.processed = true;
    if (adminNote) transaction.adminNote = adminNote;
    await transaction.save();

    // Send notification to user
    await sendNotification(
      transaction.user._id,
      "Withdrawal Approved ✅",
      `Your withdrawal of $${transaction.amount} has been approved and processed.`,
      "withdrawal",
      transaction._id,
      "transaction"
    );

    // Real-time update via WebSocket
    sendUserUpdate(transaction.user._id.toString(), {
      type: 'WITHDRAWAL_APPROVED',
      walletBalance: user.walletBalance,
      depositBalance: user.depositBalance,
      transaction: transaction,
      amount: transaction.amount,
      message: `Withdrawal of $${transaction.amount} has been approved and processed`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Withdrawal approved successfully", 
      data: { 
        transaction: transaction,
        userBalance: {
          walletBalance: user.walletBalance,
          depositBalance: user.depositBalance
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
});

app.put("/api/admin/withdrawal/:transactionId/reject", adminAuth, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { adminNote } = req.body;
    
    const transaction = await Transaction.findById(transactionId).populate('user');
    if (!transaction || transaction.type !== "withdrawal") {
      return res.status(404).json({ 
        success: false,
        message: "Withdrawal transaction not found" 
      });
    }
    
    transaction.status = "rejected";
    transaction.processed = true;
    if (adminNote) transaction.adminNote = adminNote;
    await transaction.save();

    // Send notification to user
    await sendNotification(
      transaction.user._id,
      "Withdrawal Rejected ❌",
      `Your withdrawal of $${transaction.amount} has been rejected. ${adminNote ? `Reason: ${adminNote}` : ''}`,
      "withdrawal",
      transaction._id,
      "transaction"
    );

    // Real-time update via WebSocket
    sendUserUpdate(transaction.user._id.toString(), {
      type: 'WITHDRAWAL_REJECTED',
      transaction: transaction,
      amount: transaction.amount,
      message: `Withdrawal of $${transaction.amount} has been rejected`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Withdrawal rejected successfully", 
      data: { transaction }
    });
  } catch (error) { 
    console.error('Withdrawal rejection error:', error);
    res.status(500).json({ 
      success: false,
      message: "Withdrawal rejection failed" 
    }); 
  }
});

// Enhanced Investment Approval
app.put("/api/admin/investment/:transactionId/approve", adminAuth, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { adminNote } = req.body;
    
    const transaction = await Transaction.findById(transactionId).populate('user');
    if (!transaction || transaction.type !== "investment") {
      return res.status(404).json({ 
        success: false,
        message: "Investment transaction not found" 
      });
    }
    
    if (transaction.status === "approved") {
      return res.status(400).json({ 
        success: false,
        message: "Investment already approved" 
      });
    }

    const user = await User.findById(transaction.user._id);
    
    if (user.depositBalance < transaction.amount) {
      return res.status(400).json({ 
        success: false,
        message: "User has insufficient deposit balance for this investment" 
      });
    }

    // Deduct from deposit balance and add to total invested
    user.depositBalance -= transaction.amount;
    user.totalInvested += transaction.amount;
    await user.save();

    // Create investment record
    const plans = [
      { id: "1", name: "Basic Plan", profitRate: 5 },
      { id: "2", name: "Premium Plan", profitRate: 8 },
      { id: "3", name: "VIP Plan", profitRate: 12 }
    ];
    
    const plan = plans.find(p => p.id === transaction.investmentPlan) || 
                plans.find(p => p.name === transaction.investmentPlan) ||
                plans[0];

    const investment = await Investment.create({
      user: user._id,
      transaction: transaction._id,
      planName: plan.name,
      amount: transaction.amount,
      profitRate: plan.profitRate,
      expectedProfit: transaction.amount * (plan.profitRate / 100),
      startDate: new Date(),
      endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
    });

    transaction.status = "approved";
    transaction.processed = true;
    if (adminNote) transaction.adminNote = adminNote;
    await transaction.save();

    // Send notification to user
    await sendNotification(
      transaction.user._id,
      "Investment Activated ✅",
      `Your investment of $${transaction.amount} in ${plan.name} has been activated. Expected profit: $${investment.expectedProfit.toFixed(2)}.`,
      "investment",
      transaction._id,
      "transaction"
    );

    // Real-time update via WebSocket
    sendUserUpdate(transaction.user._id.toString(), {
      type: 'INVESTMENT_APPROVED',
      walletBalance: user.walletBalance,
      depositBalance: user.depositBalance,
      totalInvested: user.totalInvested,
      transaction: transaction,
      investment: investment,
      amount: transaction.amount,
      message: `Investment of $${transaction.amount} in ${plan.name} has been activated`,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "Investment approved successfully", 
      data: { 
        transaction: transaction,
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
});

// Enhanced User Management with Real-time Updates
app.put("/api/admin/user/:userId/block", adminAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const { reason } = req.body;
    
    const user = await User.findByIdAndUpdate(
      userId, 
      { isBlocked: true }, 
      { new: true }
    ).select("-password -secretAnswer -confirmPassword");
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });
    }

    // Send notification to user
    await sendNotification(
      user._id,
      "Account Blocked ❌",
      `Your account has been blocked by administrator. ${reason ? `Reason: ${reason}` : ''}`,
      "error",
      null,
      "account"
    );

    // Real-time update via WebSocket
    sendUserUpdate(user._id.toString(), {
      type: 'ACCOUNT_BLOCKED',
      message: 'Your account has been blocked by administrator',
      reason: reason,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "User blocked successfully", 
      data: { user }
    });
  } catch (error) { 
    console.error('User block error:', error);
    res.status(500).json({ 
      success: false,
      message: "User block failed" 
    }); 
  }
});

app.put("/api/admin/user/:userId/unblock", adminAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findByIdAndUpdate(
      userId, 
      { isBlocked: false }, 
      { new: true }
    ).select("-password -secretAnswer -confirmPassword");
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });
    }

    // Send notification to user
    await sendNotification(
      user._id,
      "Account Reactivated ✅",
      "Your account has been reactivated by administrator.",
      "success",
      null,
      "account"
    );

    // Real-time update via WebSocket
    sendUserUpdate(user._id.toString(), {
      type: 'ACCOUNT_UNBLOCKED',
      message: 'Your account has been reactivated',
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: "User unblocked successfully", 
      data: { user }
    });
  } catch (error) { 
    console.error('User unblock error:', error);
    res.status(500).json({ 
      success: false,
      message: "User unblock failed" 
    }); 
  }
});

// Enhanced Profit Distribution
app.post("/api/admin/distribute-profits", adminAuth, async (req, res) => {
  try {
    const { investmentId, amount, note } = req.body;
    
    let investments;
    if (investmentId) {
      // Distribute profit for specific investment
      investments = await Investment.find({ _id: investmentId, status: "active" }).populate('user');
    } else {
      // Distribute profits for all active investments
      investments = await Investment.find({ status: "active" }).populate('user');
    }

    if (!investments || investments.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: "No active investments found" 
      });
    }

    const results = [];
    
    for (const investment of investments) {
      const profitAmount = amount || (investment.amount * investment.profitRate / 100);
      
      // Update user wallet balance
      const user = await User.findById(investment.user._id);
      user.walletBalance += profitAmount;
      investment.totalProfitEarned += profitAmount;
      
      await user.save();
      await investment.save();
      
      // Create profit transaction
      const profitTransaction = await Transaction.create({
        user: user._id,
        type: "profit",
        amount: profitAmount,
        status: "approved",
        processed: true,
        investmentPlan: investment.planName
      });
      
      // Create profit record
      await Profit.create({
        userId: user._id,
        amount: profitAmount,
        note: note || `Profit from ${investment.planName}`,
        investmentId: investment._id
      });
      
      // Send notification to user
      await sendNotification(
        user._id,
        "Profit Added 🎯",
        `You've received $${profitAmount.toFixed(2)} profit from your ${investment.planName} investment.`,
        "profit",
        profitTransaction._id,
        "transaction"
      );
      
      // Real-time update via WebSocket
      sendUserUpdate(user._id.toString(), {
        type: 'PROFIT_ADDED',
        walletBalance: user.walletBalance,
        amount: profitAmount,
        investment: investment,
        message: `You've received $${profitAmount.toFixed(2)} profit`,
        timestamp: new Date().toISOString()
      });
      
      results.push({
        userId: user._id,
        username: user.username,
        investment: investment.planName,
        profit: profitAmount,
        newBalance: user.walletBalance
      });
    }
    
    res.json({ 
      success: true,
      message: `Profits distributed to ${results.length} investments`, 
      data: { results }
    });
  } catch (error) { 
    console.error('Profit distribution error:', error);
    res.status(500).json({ 
      success: false,
      message: "Profit distribution failed" 
    }); 
  }
});

// Enhanced Admin Notification System
app.post("/api/admin/notify-user", adminAuth, async (req, res) => {
  try {
    const { userId, title, content, type } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });
    }
    
    const notification = await sendNotification(
      userId,
      title,
      content,
      type || "info"
    );
    
    // Real-time update via WebSocket
    sendUserUpdate(userId.toString(), {
      type: 'NEW_NOTIFICATION',
      notification: notification,
      message: 'You have a new notification from admin',
      timestamp: new Date().toISOString()
    });
    
    res.json({ 
      success: true,
      message: "Notification sent successfully", 
      data: { notification }
    });
  } catch (error) { 
    console.error('Admin notification error:', error);
    res.status(500).json({ 
      success: false,
      message: "Notification sending failed" 
    }); 
  }
});

app.post("/api/admin/notify-all", adminAuth, async (req, res) => {
  try {
    const { title, content, type } = req.body;
    
    const users = await User.find({});
    let sentCount = 0;
    
    for (const user of users) {
      const notification = await sendNotification(
        user._id,
        title,
        content,
        type || "info"
      );
      
      // Real-time update via WebSocket
      sendUserUpdate(user._id.toString(), {
        type: 'NEW_NOTIFICATION',
        notification: notification,
        message: 'You have a new notification from admin',
        timestamp: new Date().toISOString()
      });
      
      sentCount++;
    }
    
    res.json({ 
      success: true,
      message: `Notification sent to ${sentCount} users`, 
      data: { sentCount }
    });
  } catch (error) { 
    console.error('Bulk notification error:', error);
    res.status(500).json({ 
      success: false,
      message: "Bulk notification sending failed" 
    }); 
  }
});

// Enhanced System-wide Balance Adjustment
app.put("/api/admin/system-balance-adjustment", adminAuth, async (req, res) => {
  try {
    const { adjustmentType, amount, note } = req.body;
    
    if (!['add', 'subtract'].includes(adjustmentType)) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid adjustment type. Use 'add' or 'subtract'" 
      });
    }
    
    const users = await User.find({});
    const results = [];
    
    for (const user of users) {
      const oldBalance = user.walletBalance;
      
      if (adjustmentType === 'add') {
        user.walletBalance += amount;
      } else {
        user.walletBalance = Math.max(0, user.walletBalance - amount);
      }
      
      await user.save();
      
      // Create transaction record
      const transaction = await Transaction.create({
        user: user._id,
        type: "admin_adjustment",
        amount: adjustmentType === 'add' ? amount : -amount,
        status: "approved",
        adminNote: `System balance adjustment: ${adjustmentType} $${amount}. ${note || ''}`,
        processed: true
      });
      
      // Send notification
      await sendNotification(
        user._id,
        "Balance Adjustment",
        `Your wallet balance has been ${adjustmentType === 'add' ? 'increased' : 'decreased'} by $${amount}. ${note || ''}`,
        "balance_update",
        transaction._id,
        "transaction"
      );
      
      // Real-time update via WebSocket
      sendUserUpdate(user._id.toString(), {
        type: 'ADMIN_BALANCE_ADJUSTMENT',
        walletBalance: user.walletBalance,
        adjustmentType: adjustmentType,
        amount: amount,
        message: `Your balance has been ${adjustmentType === 'add' ? 'increased' : 'decreased'} by $${amount}`,
        timestamp: new Date().toISOString()
      });
      
      results.push({
        userId: user._id,
        username: user.username,
        oldBalance: oldBalance,
        newBalance: user.walletBalance,
        change: adjustmentType === 'add' ? amount : -amount
      });
    }
    
    res.json({ 
      success: true,
      message: `Balance adjustment applied to ${results.length} users`, 
      data: { results }
    });
  } catch (error) { 
    console.error('System balance adjustment error:', error);
    res.status(500).json({ 
      success: false,
      message: "System balance adjustment failed" 
    }); 
  }
});

// Enhanced WebSocket user update function
function sendUserUpdate(userId, data) {
  const ws = clients.get(userId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify({
        ...data,
        timestamp: new Date().toISOString()
      }));
      console.log(`✅ Real-time update sent to user ${userId}:`, data.type);
    } catch (error) {
      console.error('❌ Error sending WebSocket message:', error);
      clients.delete(userId);
    }
  } else {
    console.log(`ℹ️ User ${userId} not connected via WebSocket, update queued for next connection`);
  }
}

// Broadcast to all connected users
function broadcastToAllUsers(data) {
  clients.forEach((ws, userId) => {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify({
          ...data,
          timestamp: new Date().toISOString()
        }));
      } catch (error) {
        console.error(`Error broadcasting to user ${userId}:`, error);
        clients.delete(userId);
      }
    }
  });
}

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
  console.log(`🌍 Location tracking: Enabled with enhanced IP detection`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
  });
}); 