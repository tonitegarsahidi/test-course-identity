const serverless = require("serverless-http");
const express = require('express');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const knex = require('knex');

// Load environment variables from .env file
dotenv.config();

const app = express();
const host = process.env.HOST || 'http://localhost';
const port = process.env.PORT || 8081;

// Middleware to parse incoming JSON data
app.use(bodyParser.json());

// Database connection setup using Knex
const db = knex({
    client: 'mysql2',
    connection: {
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        port: process.env.DB_PORT,
    },
});

// Route handler for the root URL
app.get('/', (req, res) => {
    const message = "Hello I am Identity";
    res.json({ message });
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Get user from the database based on the provided email
        const user = await db('user').where('email', email).first();
        if (!user) {
            return res.status(401).json({ message: 'Authentication failed: User not found. : ' + email });
        }

        // Compare the provided password with the hashed password in the database
        const pepper = process.env.DB_PASSWORD_PEPPER; // Pepper value from .env file
        const passwordMatch = await bcrypt.compare(password + pepper, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Authentication failed: Incorrect password.' });
        }

        // Create a JWT token containing user data
        const token = jwt.sign(
            { id: user.id, email: user.email, full_name: user.full_name, phone_number: user.phone_number, role: user.roles },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ token });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'An error occurred during login.' });
    }
});

// Start the server
app.listen(port, () => {
    console.log(`IdentityService is running on ${host}:${port}`);
});

module.exports.handler = serverless(app);
