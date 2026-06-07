const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config(); // Load environment variables

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET;

// --- AUTHORIZATION MIDDLEWARE ---
const authorizeGateway = (req, res, next) => {
    const header = req.headers['authorization'];
    const token = header && header.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
        if (err) return res.status(403).json({ error: 'Forbidden' });
        req.user = decodedUser;
        next();
    });
};

// --- AUTH ROUTE ---
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const userQuery = await pool.query('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username.trim()]);
        const user = userQuery.rows[0];
        
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token, role: user.role });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ... [Keep your other endpoints here]

app.listen(process.env.PORT || 3000);
