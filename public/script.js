const apiUrl = 'http://localhost:3000';

// ==================== PASSWORD FUNCTIONS ====================

function togglePassword(id) {
  const input = document.getElementById(id);
  if (input) {
    input.type = input.type === 'password' ? 'text' : 'password';
  }
}

function checkPasswordStrength(password) {
  const strength = document.getElementById('passwordStrength');
  if (!strength) return;
  
  let score = 0;
  if (password.length >= 8) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[@$!%*?&]/.test(password)) score++;
  
  strength.textContent = score < 3 ? 'Weak' : score < 5 ? 'Medium' : 'Strong';
  strength.className = 'strength ' + (score < 3 ? 'weak' : score < 5 ? 'medium' : 'strong');
}

// ==================== WELCOME SECTION ====================

document.getElementById('showLoginBtn')?.addEventListener('click', () => {
  document.getElementById('welcomeSection').style.display = 'none';
  document.getElementById('loginSection').style.display = 'block';
});

// ==================== SIGN UP ====================

document.getElementById('signupForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const category = document.getElementById('category').value;
  const messageElem = document.getElementById('message');
  
  messageElem.textContent = '';
  messageElem.classList.remove('success', 'error');
  
  try {
    const res = await fetch(`${apiUrl}/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, category })
    });
    
    const data = await res.json();
    messageElem.textContent = data.message;
    
    if (res.status === 201) {
      document.getElementById('signupForm').style.display = 'none';
      document.getElementById('otpSection').style.display = 'block';
      messageElem.classList.add('success');
      localStorage.setItem('tempEmail', email);
    } else {
      messageElem.classList.add('error');
    }
  } catch (err) {
    messageElem.textContent = 'Error during sign-up';
    messageElem.classList.add('error');
  }
});

// ==================== VERIFY OTP (SIGNUP) ====================

async function verifyOTP() {
  const email = localStorage.getItem('tempEmail') || document.getElementById('email').value;
  const otp = document.getElementById('otp').value;
  const messageElem = document.getElementById('message');
  
  messageElem.textContent = '';
  messageElem.classList.remove('success', 'error');
  
  try {
    const res = await fetch(`${apiUrl}/verify-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, otp })
    });
    
    const data = await res.json();
    messageElem.textContent = data.message;
    
    if (res.status === 200) {
      messageElem.classList.add('success');
      localStorage.removeItem('tempEmail');
      setTimeout(() => window.location.href = '/', 3000);
    } else {
      messageElem.classList.add('error');
    }
  } catch (err) {
    messageElem.textContent = 'Error verifying OTP';
    messageElem.classList.add('error');
  }
}

// ==================== LOGIN ====================

document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const messageElem = document.getElementById('message');
  
  messageElem.textContent = '';
  messageElem.classList.remove('success', 'error');
  
  try {
    const res = await fetch(`${apiUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    const data = await res.json();
    messageElem.textContent = data.message;
    
    if (res.status === 200) {
      localStorage.setItem('tempToken', data.tempToken);
      localStorage.setItem('tempEmail', email);
      document.getElementById('loginForm').style.display = 'none';
      document.getElementById('otpSection').style.display = 'block';
      messageElem.classList.add('success');
    } else {
      messageElem.classList.add('error');
    }
  } catch (err) {
    messageElem.textContent = 'Error during login';
    messageElem.classList.add('error');
  }
});

// ==================== VERIFY LOGIN OTP ====================

async function verifyLoginOTP() {
  const email = localStorage.getItem('tempEmail') || document.getElementById('email').value;
  const otp = document.getElementById('otp').value;
  const messageElem = document.getElementById('message');
  
  messageElem.textContent = '';
  messageElem.classList.remove('success', 'error');
  
  try {
    const res = await fetch(`${apiUrl}/verify-login-otp`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('tempToken')}`
      },
      body: JSON.stringify({ email, otp })
    });
    
    const data = await res.json();
    messageElem.textContent = data.message;
    
    if (res.status === 200) {
      localStorage.setItem('token', data.token);
      localStorage.setItem('email', data.email);
      localStorage.setItem('category', data.category);
      localStorage.removeItem('tempToken');
      localStorage.removeItem('tempEmail');
      messageElem.classList.add('success');
      setTimeout(() => window.location.href = '/dashboard', 1000);
    } else {
      messageElem.classList.add('error');
    }
  } catch (err) {
    messageElem.textContent = 'Error verifying OTP';
    messageElem.classList.add('error');
  }
}

// ==================== FORGOT PASSWORD ====================

document.getElementById('forgotPasswordForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const messageElem = document.getElementById('message');
  
  messageElem.textContent = '';
  messageElem.classList.remove('success', 'error');
  
  try {
    const res = await fetch(`${apiUrl}/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    
    const data = await res.json();
    messageElem.textContent = data.message;
    
    if (res.status === 200) {
      document.getElementById('forgotPasswordForm').style.display = 'none';
      document.getElementById('resetSection').style.display = 'block';
      messageElem.classList.add('success');
      localStorage.setItem('resetEmail', email);
    } else {
      messageElem.classList.add('error');
    }
  } catch (err) {
    messageElem.textContent = 'Error sending OTP';
    messageElem.classList.add('error');
  }
});

// ==================== RESET PASSWORD ====================

async function resetPassword() {
  const email = localStorage.getItem('resetEmail') || document.getElementById('email').value;
  const otp = document.getElementById('otp').value;
  const newPassword = document.getElementById('newPassword').value;
  const messageElem = document.getElementById('message');
  
  messageElem.textContent = '';
  messageElem.classList.remove('success', 'error');
  
  try {
    const res = await fetch(`${apiUrl}/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, otp, newPassword })
    });
    
    const data = await res.json();
    messageElem.textContent = data.message;
    
    if (res.status === 200) {
      messageElem.classList.add('success');
      localStorage.removeItem('resetEmail');
      setTimeout(() => window.location.href = '/', 3000);
    } else {
      messageElem.classList.add('error');
    }
  } catch (err) {
    messageElem.textContent = 'Error resetting password';
    messageElem.classList.add('error');
  }
}

// ==================== CHANGE PASSWORD (DASHBOARD) ====================

function changePassword() {
  const changePasswordSection = document.getElementById('changePasswordSection');
  if (changePasswordSection) {
    changePasswordSection.style.display = 'block';
  }
}

async function submitChangePassword() {
  const email = localStorage.getItem('email');
  const oldPassword = document.getElementById('oldPassword')?.value;
  const newPassword = document.getElementById('newPassword')?.value;
  const messageElem = document.getElementById('message');
  
  if (!email || !oldPassword || !newPassword) {
    if (messageElem) {
      messageElem.textContent = 'Please fill in all fields';
      messageElem.classList.add('error');
    }
    return;
  }
  
  messageElem.textContent = '';
  messageElem.classList.remove('success', 'error');
  
  try {
    const res = await fetch(`${apiUrl}/change-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, oldPassword, newPassword })
    });
    
    const data = await res.json();
    messageElem.textContent = data.message;
    
    if (res.status === 200) {
      messageElem.classList.add('success');
      document.getElementById('changePasswordSection').style.display = 'none';
      document.getElementById('oldPassword').value = '';
      document.getElementById('newPassword').value = '';
    } else {
      messageElem.classList.add('error');
    }
  } catch (err) {
    messageElem.textContent = 'Error changing password';
    messageElem.classList.add('error');
  }
}

// ==================== LOGOUT ====================

async function logout() {
  try {
    await fetch(`${apiUrl}/logout`, { method: 'POST' });
  } catch (err) {
    console.log('Logout error:', err);
  }
  
  localStorage.clear();
  window.location.href = '/';
}

// ==================== PASSWORD INPUT LISTENERS ====================

document.getElementById('password')?.addEventListener('input', (e) => {
  checkPasswordStrength(e.target.value);
});

document.getElementById('newPassword')?.addEventListener('input', (e) => {
  checkPasswordStrength(e.target.value);
});

// ==================== SESSION TIMEOUT ====================

setTimeout(() => {
  if (localStorage.getItem('token')) {
    logout();
    alert('Session expired. Please log in again.');
  }
}, 15 * 60 * 1000);

// ==================== APPLICATION SUBMISSION ====================

document.getElementById('applicationForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const formData = new FormData(e.target);
  const messageElem = document.getElementById('applicationMessage');
  const submitBtn = e.target.querySelector('button[type="submit"]');
  
  if (messageElem) {
    messageElem.textContent = '';
    messageElem.classList.remove('success', 'error');
  }
  
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Submitting...';
  }
  
  try {
    const token = localStorage.getItem('token');
    const res = await fetch(`${apiUrl}/apply`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      },
      body: formData
    });
    
    const data = await res.json();
    
    if (messageElem) {
      messageElem.textContent = data.message;
      
      if (res.ok) {
        messageElem.classList.add('success');
        e.target.reset();
        setTimeout(() => {
          window.location.reload();
        }, 2000);
      } else {
        messageElem.classList.add('error');
      }
    }
  } catch (err) {
    if (messageElem) {
      messageElem.textContent = 'Error submitting application: ' + err.message;
      messageElem.classList.add('error');
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Submit Application';
    }
  }
});