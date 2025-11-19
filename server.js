const express = require('express');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require('multer');
const nodemailer = require('nodemailer');
const fs = require('fs');
require('dotenv').config();

const app = express();

// ===============================
//  ✔ FIXED MONGO CONNECTION
// ===============================
const MONGO_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/pembo-system';

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✔ MongoDB connected:", MONGO_URI))
.catch(err => console.error("❌ MongoDB Error:", err));


// ===============================
//  ✔ FIXED SESSION STORE
// ===============================
const store = new MongoDBStore({
  uri: MONGO_URI,       // IMPORTANT FIX
  collection: 'sessions'
});

store.on('error', function (error) {
  console.error("❌ Session Store Error:", error);
});


// ===============================
//  EXPRESS SESSION
// ===============================
app.use(session({
  secret: process.env.SESSION_SECRET || "fallback_secret",
  resave: false,
  saveUninitialized: false,
  store: store,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7,  // 7 days
    httpOnly: true,
    secure: false                    // set true if HTTPS
  }
}));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ✅ FIXED: Multer configuration with file validation
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  // Accept images only
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  store: store
}));

// ==================== SCHEMAS ====================

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  role: { type: String, default: 'resident' },
  category: String,
  otp: String,
  otpExpires: Date,
  info: String,
  documents: [String]
});
const User = mongoose.model('User', userSchema);

// 🆕 APPLICATION SCHEMA WITH GCASH PAYMENT
const applicationSchema = new mongoose.Schema({
  email: String,
  type: String,
  firstName: String,
  middleName: String,
  lastName: String,
  dateOfBirth: Date,
  contact: String,
  address: String,
  purpose: String,
  validId: String,
  proofOfAddress: String,
  documents: [String],
  gcashReference: String,
  paymentAmount: Number,
  paymentStatus: { type: String, default: 'Pending' },
  deliveryMethod: { type: String, enum: ['pickup', 'deliver'], default: 'pickup' },
  deliveryStatus: { type: String, default: null },
  deliveryStatusDate: { type: Date, default: null },  // 🆕
  status: { type: String, default: 'Pending' },
  createdAt: { type: Date, default: Date.now }
});

const Application = mongoose.model('Application', applicationSchema);

const complaintSchema = new mongoose.Schema({
  email: String,
  category: String,
  subject: String,
  location: String,
  description: String,
  contact: String,
  evidence: String,
  status: { type: String, default: 'Pending' },
  response: String,
  createdAt: { type: Date, default: Date.now }
});
const Complaint = mongoose.model('Complaint', complaintSchema);

const appointmentSchema = new mongoose.Schema({
  email: String,
  purpose: String,
  date: Date,
  time: String,
  contact: String,
  notes: String,
  certificateData: {
    fullName: String,
    dateOfBirth: Date,
    age: Number,
    sex: String,
    address: String,
    residency: Number,
    contact: String,
    certificateType: String,
    certificatePurpose: String
  },
  status: { type: String, default: 'Pending' },
  createdAt: { type: Date, default: Date.now }
});
const Appointment = mongoose.model('Appointment', appointmentSchema);

const paymentSchema = new mongoose.Schema({
  email: String,
  applicationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Application' },
  amount: Number,
  paymentMethod: String,
  referenceNumber: String,
  status: { type: String, default: 'Pending' },
  createdAt: { type: Date, default: Date.now }
});
const Payment = mongoose.model('Payment', paymentSchema);

// ==================== NODEMAILER SETUP ====================

// ==================== NODEMAILER SETUP (FIXED) ====================

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,  // ✅ CHANGED FROM 465 TO 587
  secure: false,  // ✅ CHANGED FROM true TO false (for port 587)
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  connectionTimeout: 10000,  // ✅ ADD THIS - 10 seconds timeout
  socketTimeout: 10000,      // ✅ ADD THIS - 10 seconds socket timeout
});

// ✅ TEST CONNECTION ON SERVER START
transporter.verify((error, success) => {
  if (error) {
    console.error("❌ EMAIL CONFIG ERROR:", error);
  } else {
    console.log("✅ EMAIL SERVICE READY - Can send emails!");
  }
});

// ==================== SEND MAIL WRAPPER (OPTIONAL BUT RECOMMENDED) ====================

const sendEmail = async (mailOptions) => {
  try {
    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Email sent to ${mailOptions.to}: ${info.messageId}`);
    return info;
  } catch (error) {
    console.error(`❌ EMAIL FAILED to ${mailOptions.to}:`, error.message);
    throw error;
  }
};

// ==================== MIDDLEWARE ====================

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET || 'your-jwt-secret', (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user?.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
  next();
};

// ==================== AUTH ROUTES ====================

app.post('/signup', async (req, res) => {
  try {
    const { email, password, category, adminCode } = req.body;
    
    console.log('📝 Signup attempt:', { email, category, adminCode }); // Debug log
    
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already registered' });
    
    // ✅ FIXED: CHECK ADMIN CODE FIRST (case-insensitive)
    let role = 'resident';
    
    if (category && category.trim().toLowerCase() === 'admin') {
      const correctAdminCode = process.env.ADMIN_SECRET_CODE || 'PEMBO2024ADMIN';
      
      console.log('🔑 Admin signup detected');
      console.log('Expected code:', correctAdminCode);
      console.log('Received code:', adminCode);
      
      if (!adminCode) {
        return res.status(400).json({ message: 'Admin verification code is required' });
      }
      
      if (adminCode.trim() !== correctAdminCode.trim()) {
        console.log('❌ Admin code mismatch!');
        return res.status(403).json({ message: 'Invalid admin verification code. Please contact barangay office.' });
      }
      
      role = 'admin';
      console.log('✅ Admin code verified, role set to admin');
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    
    const user = new User({ 
      email, 
      password: hashedPassword, 
      category, 
      role: role,  // ✅ Use the role we determined above
      otp, 
      otpExpires 
    });
    
    await user.save();
    
    console.log('✅ User created with role:', role);

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: role === 'admin' ? 'Admin Account Verification - Barangay Pembo' : 'Verify Your Pembo System Account',
      text: `Your OTP is ${otp}. It expires in 10 minutes.${role === 'admin' ? '\n\nThis is an ADMIN account registration.' : ''}`
    });

    res.status(201).json({ 
      message: 'Signup successful, please verify OTP',
      isAdmin: role === 'admin'
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error: ' + err.message });
  }
});
app.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });
    if (!user || user.otp !== otp || user.otpExpires < new Date()) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();
    res.json({ message: 'OTP verified, redirecting...' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ✅ FIXED: Regular Login with OTP
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }
    
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Login Verification OTP - Barangay Pembo',
      text: `Your login OTP is ${otp}. It expires in 10 minutes.`
    });

    const tempToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your-jwt-secret', { expiresIn: '10m' });
    
    res.json({ 
      success: true,
      message: 'OTP sent to your email', 
      tempToken 
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ✅ FIXED: Verify Login OTP
app.post('/verify-login-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });
    
    if (!user || user.otp !== otp || user.otpExpires < new Date()) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }
    
    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email }, 
      process.env.JWT_SECRET || 'your-jwt-secret', 
      { expiresIn: '1h' }
    );
    
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();
    
    res.json({ 
      message: 'Login successful', 
      token, 
      email: user.email, 
      category: user.category,
      role: user.role
    });
  } catch (err) {
    console.error('OTP verification error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ✅ FIXED: Admin Login with OTP
app.post('/admin-login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Admin login attempt:', email);
    
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }
    
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: 'Incorrect password' });
    }
    
    if (user.role !== 'admin') {
      return res.status(401).json({ success: false, message: 'Not an admin account' });
    }
    
    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();

    console.log('Admin OTP generated:', otp);

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Admin Login OTP - Barangay Pembo',
      text: `Your admin login OTP is ${otp}. It expires in 10 minutes.\n\nIf you did not attempt to login, please contact support immediately.`
    });

    const tempToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your-jwt-secret', { expiresIn: '10m' });
    
    res.json({ 
      success: true, 
      message: 'OTP sent to your admin email',
      requiresOTP: true,
      tempToken
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ✅ Admin OTP Verification
app.post('/verify-admin-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    console.log('Admin OTP verification:', email);
    
    const user = await User.findOne({ email });
    
    if (!user || user.otp !== otp || user.otpExpires < new Date()) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }
    
    if (user.role !== 'admin') {
      return res.status(403).json({ message: 'Not an admin account' });
    }
    
    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email }, 
      process.env.JWT_SECRET || 'your-jwt-secret', 
      { expiresIn: '1h' }
    );
    
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();
    
    console.log('Admin logged in successfully');
    
    res.json({ 
      message: 'Admin login successful', 
      token, 
      email: user.email, 
      role: user.role
    });
  } catch (err) {
    console.error('Admin OTP error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Email not found' });
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is ${otp}. It expires in 10 minutes.`
    });

    res.status(200).json({ message: 'OTP sent to your email' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    const user = await User.findOne({ email });
    if (!user || user.otp !== otp || user.otpExpires < new Date()) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();
    res.status(200).json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/logout', (req, res) => {
  try {
    req.session.destroy(err => {
      if (err) return res.status(500).json({ message: 'Logout failed' });
      res.json({ message: 'Logged out' });
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== APPLICATION ROUTES ====================

// ✅ UPDATED: Application with proper file validation and data storage
app.post('/apply', authenticateToken, upload.fields([
  { name: 'validId', maxCount: 1 },
  { name: 'proofOfAddress', maxCount: 1 }
]), async (req, res) => {
  try {
    const { email, type, firstName, middleName, lastName, dateOfBirth, contact, address, purpose, gcashReference, paymentAmount } = req.body;
    
    // ✅ Validate required fields
    if (!email || !type || !firstName || !lastName || !dateOfBirth || !contact || !address) {
      return res.status(400).json({ 
        message: 'All required fields must be filled' 
      });
    }
    
    // ✅ Validate required files
    if (!req.files || !req.files['validId'] || !req.files['proofOfAddress']) {
      return res.status(400).json({ 
        message: 'Both Valid ID and Proof of Address are required' 
      });
    }
    
    const validIdPath = req.files['validId'][0].path;
    const proofOfAddressPath = req.files['proofOfAddress'][0].path;
    
    // ✅ Create application with all data INCLUDING GCASH PAYMENT
const application = new Application({ 
  email, 
  type,
  firstName,
  middleName,
  lastName,
  dateOfBirth,
  contact,
  address,
  purpose,
  validId: validIdPath,
  proofOfAddress: proofOfAddressPath,
  documents: [validIdPath, proofOfAddressPath],
  gcashReference,              // 🆕 GCash reference
  paymentAmount: paymentAmount || 100,  // 🆕 Default ₱100
  paymentStatus: 'Pending',    // 🆕 Payment verification status
  deliveryMethod: req.body.deliveryMethod || 'pickup',
  status: 'Pending'
});
    
    await application.save();
    
    console.log('✅ Application saved with files:', {
      email,
      type,
      validId: validIdPath,
      proofOfAddress: proofOfAddressPath
    });
    
    res.status(200).json({ 
      message: 'Application submitted successfully',
      application: {
        id: application._id,
        type: application.type,
        status: application.status,
        hasValidId: !!application.validId,
        hasProofOfAddress: !!application.proofOfAddress
      }
    });
  } catch (err) {
    console.error('Application error:', err);
    res.status(500).json({ message: 'Server error: ' + err.message });
  }
});

app.get('/applications/my', authenticateToken, async (req, res) => {
  try {
    const applications = await Application.find({ email: req.user.email })
      .sort({ createdAt: -1 });
    res.json({ applications });
  } catch (err) {
    console.error('Error fetching user applications:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ✅ FIXED: Admin applications endpoint
app.get('/admin/applications', authenticateToken, isAdmin, async (req, res) => {
  try {
    const applications = await Application.find().sort({ createdAt: -1 });
    res.json(applications);
  } catch (err) {
    console.error('Error fetching applications:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/admin/approve', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id, status } = req.body;
    
    console.log('📋 Updating application:', id, 'to status:', status);
    
    const application = await Application.findByIdAndUpdate(id, { status }, { new: true });
    
    if (!application) {
      return res.status(404).json({ message: 'Application not found' });
    }
    
    console.log('✅ Application updated:', application.email, 'Status:', status);
    
    // SEND EMAIL BASED ON STATUS
    try {
      if (status === 'Approved') {
        console.log('📧 Sending APPROVAL email to:', application.email);
        
        const deliveryMessage = application.deliveryMethod === 'deliver'
          ? `Your ${application.type} will be delivered to your registered address within 24 hours. Please ensure someone is available to receive the document.`
          : `Your ${application.type} is ready for pickup at the Barangay Hall. You may claim it after 24 hours during office hours (8:00 AM - 5:00 PM, Monday to Friday).`;
        
        await transporter.sendMail({
  from: process.env.EMAIL_USER,
  to: application.email,
  subject: `Application Approved - ${application.type}`,
  html: `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #10b981;">✅ Your Application Has Been Approved</h2>
      <p>Dear ${application.firstName} ${application.lastName},</p>
      <p>We are pleased to inform you that your application for <strong>${application.type}</strong> has been approved.</p>
      
      <div style="background: #f0f9ff; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3 style="color: #0891b2; margin-top: 0;">📋 Application Details:</h3>
        <p><strong>Document Type:</strong> ${application.type}</p>
        <p><strong>Application ID:</strong> ${application._id}</p>
        <p><strong>Delivery Method:</strong> ${application.deliveryMethod === 'deliver' ? 'Home Delivery' : 'Pickup at Barangay Hall'}</p>
      </div>
      
      <div style="background: #fef3c7; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3 style="color: #92400e; margin-top: 0;">📌 Important Notice:</h3>
        <p>${deliveryMessage}</p>
      </div>
      
      <div style="background: #e0e7ff; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3 style="color: #3730a3; margin-top: 0;">📬 IMPORTANT: Confirm Receipt</h3>
        <p style="color: #4338ca; font-weight: 600;">Once you receive your ${application.type}, please log in to the resident portal and click the "RECEIVED" or "DID NOT RECEIVE" button in your applications page.</p>
        <p style="color: #4338ca; margin-top: 10px;">
          • Click "✅ Received" if you got your document<br>
          • Click "❌ Did Not Receive" if you haven't received it after 24+ hours
        </p>
        <p style="color: #4338ca; margin-top: 10px; font-style: italic;">
          This helps us improve our service and track document delivery.
        </p>
      </div>
      
      <p>If you have any questions, please contact the Barangay Hall during office hours.</p>
      
      <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
      <p style="color: #6b7280; font-size: 14px;">
        <strong>Barangay Pembo</strong><br>
        Office Hours: Monday - Friday, 8:00 AM - 5:00 PM<br>
        Contact: brgy.pembo.taguigcity@gmail.com
      </p>
    </div>
  `
});
        
        console.log('✅ Approval email sent successfully');
      } 
      else if (status === 'Rejected' || status === 'Reject') {
        console.log('📧 Sending REJECTION email to:', application.email);
        
        const emailResult = await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: application.email,
          subject: `Application Update - ${application.type}`,
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #dc2626;">📋 Application Status Update</h2>
              <p>Dear ${application.firstName} ${application.lastName},</p>
              <p>We regret to inform you that your application for <strong>${application.type}</strong> requires further review.</p>
              
              <div style="background: #fef2f2; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3 style="color: #991b1b; margin-top: 0;">Application Details:</h3>
                <p><strong>Document Type:</strong> ${application.type}</p>
                <p><strong>Application ID:</strong> ${application._id}</p>
                <p><strong>Status:</strong> Under Review</p>
              </div>
              
              <div style="background: #fffbeb; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3 style="color: #92400e; margin-top: 0;">📌 Next Steps:</h3>
                <p>Please visit the Barangay Hall during office hours for clarification on your application requirements.</p>
                <p><strong>Office Hours:</strong> Monday - Friday, 8:00 AM - 5:00 PM</p>
                <p>You may also contact us via email for inquiries.</p>
              </div>
              
              <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
              <p style="color: #6b7280; font-size: 14px;">
                <strong>Barangay Pembo</strong><br>
                Office Hours: Monday - Friday, 8:00 AM - 5:00 PM<br>
                Email: brgy.pembo.taguigcity@gmail.com
              </p>
            </div>
          `
        });
        
        console.log('✅ Rejection email sent successfully. MessageID:', emailResult.messageId);
      }
      else {
        console.log('⚠️ Status is neither Approved nor Rejected:', status);
      }
    } catch (emailError) {
      console.error('❌ EMAIL ERROR:', emailError);
      console.error('Email details:', {
        from: process.env.EMAIL_USER,
        to: application.email,
        status: status
      });
    }
    
    res.json({ message: 'Application updated', application });
  } catch (err) {
    console.error('❌ Update application error:', err);
    res.status(500).json({ message: 'Server error: ' + err.message });
  }
});

// ==================== OTHER ROUTES ====================

app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ info: user.info, documents: user.documents });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/profile', authenticateToken, async (req, res) => {
  try {
    const { email, info, documents } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.info = info;
    user.documents = documents;
    await user.save();
    res.status(200).json({ message: 'Profile updated' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/appointment', authenticateToken, async (req, res) => {
  try {
    const { email, purpose, date, time, contact, notes, certificateData } = req.body;
    
    const existingAppointment = await Appointment.findOne({ 
      email, 
      date: new Date(date), 
      time, 
      status: { $in: ['Pending', 'Confirmed'] }
    });
    
    if (existingAppointment) {
      return res.status(400).json({ message: 'You already have an appointment scheduled for this date and time' });
    }
    
    const appointment = new Appointment({ 
      email, 
      purpose, 
      date: new Date(date), 
      time, 
      contact, 
      notes,
      certificateData: purpose === 'Request for Certificate' ? certificateData : null,
      status: 'Pending'
    });
    
    await appointment.save();
    
    console.log('✅ Appointment created:', appointment._id);
    
    res.status(200).json({ 
      message: 'Appointment scheduled successfully', 
      appointment 
    });
  } catch (err) {
    console.error('Appointment error:', err);
    res.status(500).json({ message: 'Server error: ' + err.message });
  }
});

app.get('/appointments/my', async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }
    
    const appointments = await Appointment.find({ email }).sort({ createdAt: -1 });
    res.json({ appointments });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// 🆕 CONFIRM OR CANCEL APPOINTMENT
app.put('/admin/appointment/update', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id, status } = req.body;
    
    console.log('📋 Updating appointment:', id, 'to status:', status);
    
    const appointment = await Appointment.findByIdAndUpdate(
      id, 
      { status }, 
      { new: true }
    );
    
    if (!appointment) {
      return res.status(404).json({ message: 'Appointment not found' });
    }
    
    console.log('✅ Appointment updated:', appointment.email, 'Status:', status);
    
    // 🆕 SEND EMAIL NOTIFICATION
    try {
      if (status === 'Confirmed') {
        console.log('📧 Sending CONFIRMATION email to:', appointment.email);
        
        let certificateDetails = '';
        if (appointment.certificateData) {
          certificateDetails = `
            <div style="background: #f0f9ff; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <h3 style="color: #0891b2; margin-top: 0;">📜 Certificate Request Details:</h3>
              <p><strong>Full Name:</strong> ${appointment.certificateData.fullName}</p>
              <p><strong>Certificate Type:</strong> ${appointment.certificateData.certificateType}</p>
              <p><strong>Purpose:</strong> ${appointment.certificateData.certificatePurpose}</p>
            </div>
          `;
        }
        
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: appointment.email,
          subject: 'Appointment Confirmed - Barangay Pembo',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <div style="background: linear-gradient(135deg, #667eea, #764ba2); padding: 30px; border-radius: 15px 15px 0 0; text-align: center;">
                <h1 style="color: white; margin: 0;">✅ Appointment Confirmed</h1>
              </div>
              
              <div style="background: white; padding: 30px; border: 1px solid #e5e7eb; border-top: none;">
                <p style="font-size: 16px; color: #333; margin-bottom: 20px;">Dear Resident,</p>
                
                <p style="color: #555; line-height: 1.6;">
                  This is to confirm your scheduled appointment with Barangay Pembo. Please take note of the following details:
                </p>
                
                <div style="background: #f0fdf4; padding: 20px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #10b981;">
                  <h3 style="color: #065f46; margin-top: 0;">📅 Appointment Details:</h3>
                  <p style="margin: 8px 0;"><strong>Purpose:</strong> ${appointment.purpose}</p>
                  <p style="margin: 8px 0;"><strong>Date:</strong> ${new Date(appointment.date).toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</p>
                  <p style="margin: 8px 0;"><strong>Time:</strong> ${appointment.time}</p>
                  <p style="margin: 8px 0;"><strong>Contact:</strong> ${appointment.contact}</p>
                  ${appointment.notes ? `<p style="margin: 8px 0;"><strong>Notes:</strong> ${appointment.notes}</p>` : ''}
                </div>
                
                ${certificateDetails}
                
                <div style="background: #fffbeb; padding: 20px; border-radius: 8px; margin: 25px 0;">
                  <h3 style="color: #92400e; margin-top: 0;">📌 Important Reminders:</h3>
                  <ul style="color: #78350f; margin: 10px 0; padding-left: 20px;">
                    <li style="margin-bottom: 8px;">Please arrive 10 minutes before your scheduled time</li>
                    <li style="margin-bottom: 8px;">Bring a valid ID for verification</li>
                    <li style="margin-bottom: 8px;">Wear appropriate attire</li>
                    <li style="margin-bottom: 8px;">If you cannot attend, please inform us at least 24 hours in advance</li>
                  </ul>
                </div>
                
                <p style="color: #555; line-height: 1.6; margin-top: 25px;">
                  Should you have any questions or need to reschedule, please contact the Barangay Hall during office hours.
                </p>
                
                <p style="color: #555; margin-top: 25px;">
                  Thank you for your cooperation.
                </p>
                
                <p style="color: #555; margin-top: 15px;">
                  Respectfully yours,<br>
                  <strong>Barangay Pembo Office</strong>
                </p>
              </div>
              
              <div style="background: #f9fafb; padding: 20px; border-radius: 0 0 15px 15px; text-align: center; border: 1px solid #e5e7eb; border-top: none;">
                <p style="color: #6b7280; font-size: 14px; margin: 5px 0;">
                  <strong>Barangay Pembo</strong>
                </p>
                <p style="color: #6b7280; font-size: 13px; margin: 5px 0;">
                  Office Hours: Monday - Friday, 8:00 AM - 5:00 PM
                </p>
                <p style="color: #6b7280; font-size: 13px; margin: 5px 0;">
                  Email: brgy.pembo.taguigcity@gmail.com
                </p>
              </div>
            </div>
          `
        });
        
        console.log('✅ Confirmation email sent');
      } 
      else if (status === 'Cancelled' || status === 'Canceled') {
        console.log('📧 Sending CANCELLATION email to:', appointment.email);
        
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: appointment.email,
          subject: 'Appointment Cancelled - Barangay Pembo',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <div style="background: linear-gradient(135deg, #dc2626, #991b1b); padding: 30px; border-radius: 15px 15px 0 0; text-align: center;">
                <h1 style="color: white; margin: 0;">❌ Appointment Cancelled</h1>
              </div>
              
              <div style="background: white; padding: 30px; border: 1px solid #e5e7eb; border-top: none;">
                <p style="font-size: 16px; color: #333; margin-bottom: 20px;">Dear Resident,</p>
                
                <p style="color: #555; line-height: 1.6;">
                  We regret to inform you that your scheduled appointment with Barangay Pembo has been cancelled. Please see the details below:
                </p>
                
                <div style="background: #fef2f2; padding: 20px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #dc2626;">
                  <h3 style="color: #991b1b; margin-top: 0;">📅 Cancelled Appointment:</h3>
                  <p style="margin: 8px 0;"><strong>Purpose:</strong> ${appointment.purpose}</p>
                  <p style="margin: 8px 0;"><strong>Date:</strong> ${new Date(appointment.date).toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</p>
                  <p style="margin: 8px 0;"><strong>Time:</strong> ${appointment.time}</p>
                </div>
                
                <div style="background: #fffbeb; padding: 20px; border-radius: 8px; margin: 25px 0;">
                  <h3 style="color: #92400e; margin-top: 0;">📌 Next Steps:</h3>
                  <p style="color: #78350f; line-height: 1.6;">
                    If you wish to reschedule your appointment, please visit our office during business hours or schedule a new appointment through the resident portal.
                  </p>
                  <p style="color: #78350f; line-height: 1.6; margin-top: 10px;">
                    For urgent matters, you may visit the Barangay Hall directly during office hours or contact us via email.
                  </p>
                </div>
                
                <p style="color: #555; line-height: 1.6; margin-top: 25px;">
                  We apologize for any inconvenience this may have caused.
                </p>
                
                <p style="color: #555; margin-top: 25px;">
                  Respectfully yours,<br>
                  <strong>Barangay Pembo Office</strong>
                </p>
              </div>
              
              <div style="background: #f9fafb; padding: 20px; border-radius: 0 0 15px 15px; text-align: center; border: 1px solid #e5e7eb; border-top: none;">
                <p style="color: #6b7280; font-size: 14px; margin: 5px 0;">
                  <strong>Barangay Pembo</strong>
                </p>
                <p style="color: #6b7280; font-size: 13px; margin: 5px 0;">
                  Office Hours: Monday - Friday, 8:00 AM - 5:00 PM
                </p>
                <p style="color: #6b7280; font-size: 13px; margin: 5px 0;">
                  Email: brgy.pembo.taguigcity@gmail.com
                </p>
              </div>
            </div>
          `
        });
        
        console.log('✅ Cancellation email sent');
      }
    } catch (emailError) {
      console.error('❌ EMAIL ERROR:', emailError);
    }
    
    res.json({ message: 'Appointment updated successfully', appointment });
  } catch (err) {
    console.error('❌ Update appointment error:', err);
    res.status(500).json({ message: 'Server error: ' + err.message });
  }
});

app.get('/appointments', authenticateToken, isAdmin, async (req, res) => {
  try {
    const appointments = await Appointment.find().sort({ createdAt: -1 });
    res.json(appointments);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/complaint', async (req, res) => {
  try {
    const { email, category, subject, location, description, contact, evidence } = req.body;
    
    const complaint = new Complaint({ 
      email, 
      category, 
      subject, 
      location, 
      description, 
      contact, 
      evidence 
    });
    
    await complaint.save();
    res.status(200).json({ 
      message: 'Complaint submitted successfully', 
      complaint 
    });
  } catch (err) {
    console.error('Complaint error:', err);
    res.status(500).json({ message: 'Server error: ' + err.message });
  }
});

app.get('/complaints/my', async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }
    
    const complaints = await Complaint.find({ email }).sort({ createdAt: -1 });
    res.json({ complaints });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/complaints', authenticateToken, isAdmin, async (req, res) => {
  try {
    const complaints = await Complaint.find().sort({ createdAt: -1 });
    res.json(complaints);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/complaint/response', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id, response } = req.body;
    await Complaint.findByIdAndUpdate(id, { status: 'Resolved', response });
    res.json({ message: 'Complaint resolved' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/notify', authenticateToken, async (req, res) => {
  try {
    const { email, message } = req.body;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Pembo System Notification',
      text: message
    });
    res.status(200).json({ message: 'Notification sent' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/dashboard.html'));
});

app.get('/dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/dashboard.html'));
});

app.get('/admin/residents', authenticateToken, isAdmin, async (req, res) => {
  try {
    const residents = await User.find({ role: 'resident' }).select('-password -otp -otpExpires');
    res.json(residents);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/admin/residents/count', authenticateToken, isAdmin, async (req, res) => {
  try {
    const count = await User.countDocuments({ role: 'resident' });
    res.json({ count });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/admin/resident/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { info, status } = req.body;
    
    const resident = await User.findByIdAndUpdate(
      id, 
      { info, status },
      { new: true }
    ).select('-password -otp -otpExpires');
    
    if (!resident) {
      return res.status(404).json({ message: 'Resident not found' });
    }
    
    res.json({ message: 'Resident updated successfully', resident });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/admin/resident/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const resident = await User.findByIdAndDelete(id);
    
    if (!resident) {
      return res.status(404).json({ message: 'Resident not found' });
    }
    
    res.json({ message: 'Resident deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/admin/payments', authenticateToken, isAdmin, async (req, res) => {
  try {
    const payments = await Payment.find().sort({ createdAt: -1 });
    res.json(payments);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/admin/payment/verify', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id, status } = req.body;
    const payment = await Payment.findByIdAndUpdate(
      id, 
      { status },
      { new: true }
    );
    
    if (!payment) {
      return res.status(404).json({ message: 'Payment not found' });
    }
    
    res.json({ message: 'Payment updated successfully', payment });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/payment', authenticateToken, async (req, res) => {
  try {
    const { email, applicationId, amount, paymentMethod, referenceNumber } = req.body;
    
    const payment = new Payment({
      email,
      applicationId,
      amount,
      paymentMethod,
      referenceNumber,
      status: 'Pending'
    });
    
    await payment.save();
    res.status(201).json({ message: 'Payment submitted for verification', payment });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// 🆕 VERIFY GCASH PAYMENT FOR APPLICATION
app.put('/admin/application/verify-payment', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { applicationId, paymentStatus } = req.body;
    
    const application = await Application.findByIdAndUpdate(
      applicationId,
      { paymentStatus },
      { new: true }
    );
    
    if (!application) {
      return res.status(404).json({ message: 'Application not found' });
    }
    
    res.json({ 
      message: 'Payment status updated successfully', 
      application 
    });
  } catch (err) {
    console.error('Payment verification error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;

// 🆕 UPDATE DELIVERY STATUS FROM RESIDENT
app.put('/application/delivery-status', authenticateToken, async (req, res) => {
  try {
    const { applicationId, deliveryStatus } = req.body;
    
    const application = await Application.findByIdAndUpdate(
      applicationId,
      { 
        deliveryStatus,
        deliveryStatusDate: new Date()
      },
      { new: true }
    );
    
    if (!application) {
      return res.status(404).json({ message: 'Application not found' });
    }
    
    // 🆕 SEND EMAIL TO ADMIN
try {
    const adminUsers = await User.find({ role: 'admin' });
    const adminEmails = adminUsers.map(admin => admin.email).join(', ');
    
    if (adminEmails) {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: adminEmails,
            subject: `📬 Document Delivery Update - ${application.type}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: white; border-radius: 15px;">
                    <div style="background: ${deliveryStatus === 'Received' ? 'linear-gradient(135deg, #10b981, #059669)' : 'linear-gradient(135deg, #ef4444, #dc2626)'}; padding: 30px; border-radius: 15px 15px 0 0; text-align: center;">
                        <h1 style="color: white; margin: 0; font-size: 28px;">
                            ${deliveryStatus === 'Received' ? '✅ Document Received' : '⚠️ Document Not Received'}
                        </h1>
                    </div>
                    
                    <div style="padding: 30px; background: #f9fafb; border-radius: 0 0 15px 15px;">
                        <h2 style="color: #1f2937; margin-top: 0;">Delivery Status Update</h2>
                        
                        <div style="background: white; padding: 20px; border-radius: 10px; margin: 20px 0;">
                            <p style="margin: 8px 0; color: #374151;"><strong>Resident:</strong> ${application.firstName} ${application.lastName}</p>
                            <p style="margin: 8px 0; color: #374151;"><strong>Email:</strong> ${application.email}</p>
                            <p style="margin: 8px 0; color: #374151;"><strong>Contact:</strong> ${application.contact}</p>
                            <p style="margin: 8px 0; color: #374151;"><strong>Document Type:</strong> ${application.type}</p>
                            <p style="margin: 8px 0; color: #374151;"><strong>Delivery Method:</strong> ${application.deliveryMethod === 'deliver' ? 'Home Delivery' : 'Pickup at Barangay Hall'}</p>
                            <p style="margin: 8px 0; color: #374151;"><strong>Status:</strong> <span style="color: ${deliveryStatus === 'Received' ? '#10b981' : '#ef4444'}; font-weight: bold;">${deliveryStatus}</span></p>
                            <p style="margin: 8px 0; color: #6b7280;"><strong>Date Reported:</strong> ${new Date().toLocaleString('en-US', { dateStyle: 'full', timeStyle: 'short' })}</p>
                        </div>
                        
                        ${deliveryStatus === 'Not Received' ? `
                            <div style="background: #fee2e2; padding: 20px; border-left: 4px solid #dc2626; border-radius: 8px; margin-top: 20px;">
                                <p style="color: #991b1b; font-weight: 600; margin: 0 0 10px 0;">⚠️ Action Required</p>
                                <p style="color: #7f1d1d; margin: 0;">The resident has reported that they have NOT received their ${application.type} document. Please investigate and follow up on this delivery immediately.</p>
                            </div>
                        ` : `
                            <div style="background: #d1fae5; padding: 20px; border-left: 4px solid #10b981; border-radius: 8px; margin-top: 20px;">
                                <p style="color: #065f46; font-weight: 600; margin: 0 0 10px 0;">✅ Delivery Confirmed</p>
                                <p style="color: #047857; margin: 0;">The resident has confirmed receipt of their ${application.type}. This transaction is now complete.</p>
                            </div>
                        `}
                        
                        <div style="margin-top: 30px; padding-top: 20px; border-top: 2px solid #e5e7eb; text-align: center;">
                            <p style="color: #6b7280; font-size: 14px; margin: 5px 0;">
                                <strong>Barangay Pembo Management System</strong>
                            </p>
                            <p style="color: #9ca3af; font-size: 12px; margin: 5px 0;">
                                This is an automated notification. Please do not reply to this email.
                            </p>
                        </div>
                    </div>
                </div>
            `
        });
        console.log(`✅ Admin notification sent to: ${adminEmails}`);
    }
} catch (emailError) {
    console.error('❌ Email error:', emailError);
}
    
    res.json({ message: 'Delivery status updated', application });
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.listen(PORT, () => {
    console.log("Server running on port " + PORT);
});
