const apiUrl = 'https://barangay-pembo-system.onrender.com';

document.getElementById('showLoginBtn')?.addEventListener('click', () => {
    alert('Button clicked! Checking sections...');
    const welcomeSection = document.getElementById('welcomeSection');
    const loginSection = document.getElementById('loginSection');
    if (welcomeSection && loginSection) {
        alert('Sections found! Toggling display...');
        welcomeSection.style.display = 'none';
        loginSection.classList.add('active');
        alert('Toggle complete! Check if login form is visible.');
    } else {
        alert('Error: One or both sections not found! Check HTML IDs.');
    }
});

document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const messageElem = document.getElementById('message');
    if (!email || !password) {
        messageElem.textContent = 'Please fill in all fields';
        messageElem.classList.add('error');
        alert('Please fill in all fields.');
        return;
    }
    try {
        alert('Sending login request to server...');
        const res = await fetch(`${apiUrl}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        messageElem.textContent = data.message;
        if (res.status === 200) {
            messageElem.classList.add('success');
            localStorage.setItem('tempToken', data.tempToken);
            localStorage.setItem('email', email);
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('otpSection').style.display = 'block';
            alert('Login successful, OTP section should appear.');
        } else {
            messageElem.classList.add('error');
            alert('Login failed: ' + data.message);
        }
    } catch (err) {
        messageElem.textContent = 'Network error or server error';
        messageElem.classList.add('error');
        alert('Network error occurred. Check server or internet.');
    }
});

// Apply for document form submission
document.getElementById('applyForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const type = document.getElementById('type').value;
    const documents = document.getElementById('documents').files;
    const messageElem = document.getElementById('message');
    if (!localStorage.getItem('token')) {
        messageElem.textContent = 'Please log in to apply';
        messageElem.classList.add('error');
        return;
    }
    const formData = new FormData();
    formData.append('type', type);
    formData.append('email', localStorage.getItem('email'));
    for (let file of documents) formData.append('documents', file);
    try {
        const res = await fetch(`${apiUrl}/apply`, {
            method: 'POST',
            body: formData,
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        const data = await res.json();
        messageElem.textContent = data.message;
        if (res.status === 200) messageElem.classList.add('success');
        else messageElem.classList.add('error');
    } catch (err) {
        messageElem.textContent = 'Error submitting application';
        messageElem.classList.add('error');
    }
});

// Process payment form submission
document.getElementById('payForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const applicationId = document.getElementById('applicationId').value;
    const messageElem = document.getElementById('message');
    if (!localStorage.getItem('token')) {
        messageElem.textContent = 'Please log in to process payment';
        messageElem.classList.add('error');
        return;
    }
    try {
        const res = await fetch(`${apiUrl}/pay`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('token')}` },
            body: JSON.stringify({ email: localStorage.getItem('email'), applicationId })
        });
        const data = await res.json();
        if (res.status === 200) {
            messageElem.textContent = data.message + ' (Reference: ' + data.reference + ')';
            messageElem.classList.add('success');
        } else {
            messageElem.textContent = data.message || 'Error generating payment reference';
            messageElem.classList.add('error');
        }
    } catch (err) {
        messageElem.textContent = 'Error generating payment reference';
        messageElem.classList.add('error');
    }
});

// Load dashboard data on page load
window.onload = async () => {
    const role = localStorage.getItem('role');
    const messageElem = document.getElementById('message');
    document.getElementById('userCategory')?.textContent = `User: ${role || 'Guest'}`;
    if (!role) {
        messageElem.textContent = 'Please log in to access the dashboard';
        messageElem.classList.add('error');
        setTimeout(() => window.location.href = 'login.html', 2000);
        return;
    }
    if (role === 'resident') {
        document.getElementById('residentDashboard').style.display = 'block';
        try {
            const res = await fetch(`${apiUrl}/applications?email=${localStorage.getItem('email')}`, {
                headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
            });
            const data = await res.json();
            document.getElementById('applications').innerHTML = data.applications.map(app => `<p>${app.type} - Status: ${app.status} - ID: ${app._id}</p>`).join('');
        } catch (err) {
            messageElem.textContent = 'Error loading applications';
            messageElem.classList.add('error');
        }
    } else if (role === 'admin') {
        document.getElementById('adminDashboard').style.display = 'block';
        try {
            const appRes = await fetch(`${apiUrl}/admin/applications`, {
                headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
            });
            const appData = await appRes.json();
            document.getElementById('adminApplications').innerHTML = appData.map(app => `<p>${app.type} - ${app.email} - Status: ${app.status} - <button onclick="approve('${app._id}', 'Approved')">Approve</button><button onclick="approve('${app._id}', 'Rejected')">Reject</button></p>`).join('');
            const apptRes = await fetch(`${apiUrl}/appointments`, {
                headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
            });
            const apptData = await apptRes.json();
            document.getElementById('appointments').innerHTML = apptData.map(appt => `<p>${appt.email} - ${appt.date} - ${appt.status}</p>`).join('');
        } catch (err) {
            messageElem.textContent = 'Error loading admin data';
            messageElem.classList.add('error');
        }
    }
    if (document.getElementById('profileForm')) {
        if (!localStorage.getItem('token')) {
            messageElem.textContent = 'Please log in to view or update profile';
            messageElem.classList.add('error');
            return;
        }
        try {
            const res = await fetch(`${apiUrl}/profile`, {
                method: 'GET',
                headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
            });
            const data = await res.json();
            if (res.status === 200) {
                document.getElementById('info').value = data.info || '';
            } else {
                messageElem.textContent = data.message || 'Error loading profile';
                messageElem.classList.add('error');
            }
        } catch (err) {
            messageElem.textContent = 'Error loading profile';
            messageElem.classList.add('error');
        }
    }
};

// Profile form submission
document.getElementById('profileForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const info = document.getElementById('info').value;
    const documents = Array.from(document.getElementById('documents').files).map(f => f.name);
    const email = localStorage.getItem('email');
    const messageElem = document.getElementById('message');
    if (!localStorage.getItem('token')) {
        messageElem.textContent = 'Please log in to update profile';
        messageElem.classList.add('error');
        return;
    }
    try {
        const res = await fetch(`${apiUrl}/profile`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('token')}` },
            body: JSON.stringify({ email, info, documents })
        });
        const data = await res.json();
        messageElem.textContent = data.message;
        if (res.status === 200) messageElem.classList.add('success');
        else messageElem.classList.add('error');
    } catch (err) {
        messageElem.textContent = 'Error updating profile';
        messageElem.classList.add('error');
    }
});

// Appointment form submission
document.getElementById('appointmentForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const date = document.getElementById('date').value;
    const messageElem = document.getElementById('message');
    if (!localStorage.getItem('token')) {
        messageElem.textContent = 'Please log in to schedule an appointment';
        messageElem.classList.add('error');
        return;
    }
    try {
        const res = await fetch(`${apiUrl}/appointment`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('token')}` },
            body: JSON.stringify({ email: localStorage.getItem('email'), date })
        });
        const data = await res.json();
        messageElem.textContent = data.message;
        if (res.status === 200) messageElem.classList.add('success');
        else messageElem.classList.add('error');
    } catch (err) {
        messageElem.textContent = 'Error scheduling appointment';
        messageElem.classList.add('error');
    }
});

// Complaint form submission
document.getElementById('complaintForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const content = document.getElementById('content').value;
    const email = localStorage.getItem('email');
    const messageElem = document.getElementById('message');
    if (!localStorage.getItem('token')) {
        messageElem.textContent = 'Please log in to submit complaint';
        messageElem.classList.add('error');
        return;
    }
    try {
        const res = await fetch(`${apiUrl}/complaint`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('token')}` },
            body: JSON.stringify({ email, content })
        });
        const data = await res.json();
        messageElem.textContent = data.message;
        if (res.status === 200) {
            messageElem.classList.add('success');
            document.getElementById('content').value = ''; // Clear textarea
        } else {
            messageElem.classList.add('error');
        }
    } catch (err) {
        messageElem.textContent = 'Error submitting complaint';
        messageElem.classList.add('error');
    }
});

// Admin login form submission
document.getElementById('adminLoginForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const messageElem = document.getElementById('message');
    try {
        const res = await fetch(`${apiUrl}/admin-login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        messageElem.textContent = data.message;
        if (res.status === 200) {
            messageElem.classList.add('success');
            localStorage.setItem('token', data.token);
            localStorage.setItem('email', email);
            localStorage.setItem('role', 'admin');
            setTimeout(() => window.location.href = 'admin_dashboard.html', 1000);
        } else {
            messageElem.classList.add('error');
        }
    } catch (err) {
        messageElem.textContent = 'Error logging in';
        messageElem.classList.add('error');
    }
});

// Forgot password form submission
document.getElementById('forgotPasswordForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('forgotEmail').value;
    const messageElem = document.getElementById('resetMessage');
    try {
        const res = await fetch(`${apiUrl}/forgot-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await res.json();
        messageElem.textContent = data.message;
        if (res.status === 200) {
            messageElem.classList.add('success');
            document.getElementById('forgotPasswordForm').style.display = 'none';
            document.getElementById('resetSection').style.display = 'block';
        } else {
            messageElem.classList.add('error');
        }
    } catch (err) {
        messageElem.textContent = 'Network error';
        messageElem.classList.add('error');
    }
});

// Reset password form submission
document.getElementById('resetPasswordForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('forgotEmail').value;
    const otp = document.getElementById('resetOtp').value;
    const newPassword = document.getElementById('newPassword').value;
    const messageElem = document.getElementById('resetMessage');
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
            setTimeout(() => window.location.href = 'login.html', 2000);
        } else {
            messageElem.classList.add('error');
        }
    } catch (err) {
        messageElem.textContent = 'Network error';
        messageElem.classList.add('error');
    }
});

// Toggle password visibility
function togglePassword(fieldId) {
    const passwordField = document.getElementById(fieldId);
    const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordField.setAttribute('type', type);
    const toggleIcon = document.querySelector(`.toggle-password[onclick="togglePassword('${fieldId}')"]`);
    toggleIcon.textContent = type === 'password' ? '👁️' : '🙈';
}

// Verify OTP for login
function verifyLoginOTP() {
    const otp = document.getElementById('otp').value;
    const email = localStorage.getItem('email');
    const messageElem = document.getElementById('message');
    fetch(`${apiUrl}/verify-login-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('tempToken')}` },
        body: JSON.stringify({ email, otp })
    })
    .then(res => res.json())
    .then(data => {
        messageElem.textContent = data.message;
        if (res.status === 200) {
            messageElem.classList.add('success');
            localStorage.setItem('token', data.token);
            localStorage.setItem('role', 'resident'); // Adjust based on user data if needed
            setTimeout(() => window.location.href = 'dashboard.html', 1000);
        } else {
            messageElem.classList.add('error');
        }
    })
    .catch(err => {
        messageElem.textContent = 'Network error';
        messageElem.classList.add('error');
    });
}

// Approve application
async function approve(id, status) {
    const messageElem = document.getElementById('message');
    if (!localStorage.getItem('token')) {
        messageElem.textContent = 'Please log in to approve applications';
        messageElem.classList.add('error');
        return;
    }
    try {
        const res = await fetch(`${apiUrl}/admin/approve`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('token')}` },
            body: JSON.stringify({ id, status })
        });
        const data = await res.json();
        messageElem.textContent = data.message;
        if (res.status === 200) messageElem.classList.add('success');
        else messageElem.classList.add('error');
        window.location.reload();
    } catch (err) {
        messageElem.textContent = 'Error approving application';
        messageElem.classList.add('error');
    }
}

// Generate document
function generateDocument(id) {
    if (!localStorage.getItem('token')) {
        alert('Please log in to generate documents');
        return;
    }
    window.open(`${apiUrl}/generate-document?id=${id}`);
}

// Logout
async function logout() {
    const messageElem = document.getElementById('message');
    try {
        const res = await fetch(`${apiUrl}/logout`, { method: 'POST' });
        const data = await res.json();
        messageElem.textContent = data.message;
        if (res.status === 200) {
            localStorage.clear();
            messageElem.classList.add('success');
            setTimeout(() => window.location.href = 'login.html', 1000);
        } else {
            messageElem.classList.add('error');
        }
    } catch (err) {
        messageElem.textContent = 'Error logging out';
        messageElem.classList.add('error');
    }
}