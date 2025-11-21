require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// ✅ Connect to MongoDB
const MONGO_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/pembo-system';

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ MongoDB connected"))
.catch((err) => {
  console.error("❌ MongoDB error:", err);
  process.exit(1);
});

// User Schema
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

// Create Admin
async function createAdmin() {
  try {
    const email = 'admin@pembo.gov';
    const password = 'Admin123!'; // ⚠️ CHANGE THIS AFTER FIRST LOGIN
    
    // Check if exists
    const existing = await User.findOne({ email });
    if (existing) {
      console.log('⚠️  Admin already exists');
      existing.role = 'admin';
      existing.category = 'Admin';
      await existing.save();
      console.log('✅ Updated to admin role');
      process.exit(0);
    }

    //
    fetch('https://72.61.124.146:3000/signup', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ 
    email, 
    password, 
    category,
    adminCode: document.getElementById('adminCode').value  // ✅ DAGDAG ITO
  })
})
    // ✅ Create new admin
    const hashedPassword = await bcrypt.hash(password, 10);
    const admin = new User({
      email: email,
      password: hashedPassword,
      role: 'admin',
      category: 'Admin'
    });
    
    await admin.save();
    
    console.log('✅ Admin account created successfully!');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📧 Email:    ', email);
    console.log('🔑 Password: ', password);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('⚠️  IMPORTANT: Change password after first login!');
    
    process.exit(0);
  } catch (err) {
    console.error('❌ Error:', err);
    process.exit(1);
  }
}

createAdmin();