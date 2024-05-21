const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser= require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

// Parsing JSON body
app.use(bodyParser.json());

const secretKey = 'Snehasish_Pati@2023sl93010'; // secret key for JWT

// Dummy user data for demonstration
let users = [
    { id: 1, username: 'snehasish', role: 'admin', password: encryptPassword('India@1947') },
    { id: 2, username: 'rohit', role: 'admin', password: encryptPassword('Bits@2023') }
];

// Route accessible only by admins
app.get("/admin", authenticateToken, validateRole('admin'), (req, res) => {
    res.json({ message: "Admin route accessed successfully" });
});

// Route accesible by any authenticated user
app.get("/user", authenticateToken, (req, res) => {
    res.json({ message: "User route accessed successfully" });
});

// Route to Login
app.post('/login', (req, res) => {
    // Mocked authentication logic
    const { username, password } = req.body;
    console.log('username:', username);
    console.log('password:', password);

    // Checking if the user exists
    const user = users.find(u => u.username === username && bcrypt.compareSync(password, u.password));

    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials, Please provide valid credentials' });
    }

    // Generating JWT token
    const token = jwt.sign({ userId: user.id, role: user.role }, secretKey, { expiresIn: '2h' });

    res.json({ token });
});


// protected route accessible to authenticated users only
app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'Protected route accessed successfully' });
});

// registration route
app.post('/register', (req, res) => {
    // Mocked authentication logic
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (user) {
        return res.status(400).json({ message: 'Invalid username, username already exists' });
    }

    const encryptedPassword = encryptPassword(password);
    const userDetails = {id: users.length + 1, username: username, role: 'user', password: encryptedPassword}
    users = [...users, userDetails]

    return res.status(201).json({ message: 'User Successfully Created' });
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

//middleware to validate users role for authorization
function validateRole (role) {
    return (req, res, next) => {
        if (req.user?.role === role) {
            next();
        } else {
            return res.status(403).json({ message: "Unauthorized" });
        }
    };
};

// Function to encrypt the password using BCrypt
function encryptPassword(plainPassword) {
    try {
        const saltRounds = 10;

        const salt = bcrypt.genSaltSync(saltRounds);

        const hashedPassword = bcrypt.hashSync(plainPassword, salt);

        return hashedPassword;
    } catch (error) {
        console.error('Error hashing password:', error);
    }
}

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
