# Barangay System

A web application for a Barangay System with secure user authentication.

## Setup
1. Install Node.js, MongoDB, and Visual Studio Code.
2. Clone this repository or create the project structure as shown.
3. Run `npm install` to install dependencies.
4. Create a `.env` file with the provided email and app password.
5. Start MongoDB (`mongod`).
6. Run `node server.js` to start the server.
7. Open `http://localhost:3000` in your browser.

## Features
- Sign-up with email verification and category selection.
- Password requirements (8+ characters, uppercase, lowercase, number, special character).
- Password strength indicator.
- Show/hide password toggle.
- OTP via email for verification and password reset.
- Login with 3-attempt limit and account lock.
- Password change and reset functionality.
- Secure logout and session timeout (15 minutes).