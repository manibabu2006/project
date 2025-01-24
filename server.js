require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
const path = require('path');
const twilio = require('twilio');

const app = express();
const PORT = 3000;


// Replace with your actual Twilio credentials
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;

const twilioClient = require('twilio')(accountSid, authToken);


// MySQL Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'manibabu',
    password: 'Manibabu@123',
    database: 'user_db',
});

db.connect(err => {
    if (err) {
        console.error('Error connecting to the database:', err.message);
        process.exit(1);
    }
    console.log('Connected to the MySQL database.');
});

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Serve Static Files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'loginpage.html'));
});

// Helper: Generate OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Store OTPs Temporarily
const otpStore = {};

// Login Endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [results] = await db.promise().query('SELECT * FROM users WHERE username = ?', [username]);

        if (results.length === 0) return res.status(401).send('Invalid registation number or password');

        const user = results[0];
        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) return res.status(401).send('Invalid registation number or password');

        res.redirect('/website.html');
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Internal server error');
    }
});

// Register Endpoint
app.post('/register', async (req, res) => {
    const { username, password, mobile } = req.body;
    try {
        const [existingUsers] = await db.promise().query('SELECT * FROM users WHERE username = ?', [username]);

        if (existingUsers.length > 0) return res.status(400).send('Username already exists');

        const hashedPassword = bcrypt.hashSync(password, 10);
        await db.promise().query('INSERT INTO users (username, password, mobile) VALUES (?, ?, ?)', [username, hashedPassword, mobile]);

        res.send('Registration successful! You can now log in.');
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Internal server error');
    }
});

// Change Password Endpoint
app.post('/change-password', async (req, res) => {
    const { username, currentPassword, newPassword } = req.body;
    try {
        const [users] = await db.promise().query('SELECT * FROM users WHERE username = ?', [username]);

        if (users.length === 0) return res.status(404).send('User not found');

        const user = users[0];
        const isPasswordValid = bcrypt.compareSync(currentPassword, user.password);
        if (!isPasswordValid) return res.status(401).send('Current password is incorrect');

        const hashedNewPassword = bcrypt.hashSync(newPassword, 10);
        await db.promise().query('UPDATE users SET password = ? WHERE username = ?', [hashedNewPassword, username]);

        res.send('Password changed successfully!');
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Internal server error');
    }
});

// Send OTP Endpoint
app.post('/send-otp', async (req, res) => {
    const { username } = req.body;
    try {
        const [results] = await db.promise().query('SELECT mobile FROM users WHERE username = ?', [username]);

        if (results.length === 0) return res.status(404).send('User not found');

        const mobile = results[0].mobile;
        const otp = generateOTP();
        otpStore[mobile] = { otp, expiresAt: Date.now() + 300000 }; // OTP expires in 5 minutes

        await twilioClient.messages.create({
            body: `Your verification OTP is: ${otp}`,
            from: twilioPhoneNumber,
            to: mobile,
        });

        res.send('OTP sent successfully');
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Failed to send OTP');
    }
});

// Verify OTP Endpoint
app.post('/verify-otp', (req, res) => {
    const { username, otp } = req.body;

    db.query('SELECT mobile FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }

        if (results.length === 0) return res.status(404).send('User not found');

        const mobile = results[0].mobile;
        const storedOTP = otpStore[mobile];

        if (storedOTP && storedOTP.otp === otp && storedOTP.expiresAt > Date.now()) {
            delete otpStore[mobile];
            res.send('Mobile number verified successfully');
        } else {
            res.status(400).send('Invalid or expired OTP');
        }
    });
});

app.post('/logout', (req, res) => {
    // Clear authentication-related cookies or tokens
    res.clearCookie('authToken'); // If you are using cookies for authentication
    res.send('Logout successful');
});



// Start Server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
