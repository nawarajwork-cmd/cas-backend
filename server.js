const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware: Role-based Authorization
const authorize = (role) => (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'No token' });
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err || (role && user.role !== role)) return res.status(403).json({ error: 'Forbidden' });
        req.user = user;
        next();
    });
};
const cors = require('cors');
app.use(cors({
    origin: "https://nawarajwork-cmd.github.io", // Or replace * with "https://your-username.github.io"
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
}));

// Login Route
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password_hash))) 
            return res.status(401).json({ error: 'Invalid credentials' });
        
        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token, role: user.role });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Add Teacher
app.post('/api/admin/teachers', authorize('ADMIN'), async (req, res) => {
    const { name } = req.body;
    const count = (await pool.query('SELECT COUNT(*) FROM users WHERE role = $1', ['TEACHER'])).rows[0].count;
    const username = `e${parseInt(count) + 1}`;
    const hash = await bcrypt.hash('9876', 10);
    await pool.query('INSERT INTO users (username, password_hash, full_name, role) VALUES ($1, $2, $3, $4)', [username, hash, name, 'TEACHER']);
    res.json({ username, password: '9876' });
});

// Admin: Assign Subject to Teacher
app.post('/api/admin/assign', authorize('ADMIN'), async (req, res) => {
    const { user_id, subject_id, grade_level } = req.body;
    await pool.query('INSERT INTO teacher_assignments (user_id, subject_id, grade_level) VALUES ($1, $2, $3)', [user_id, subject_id, grade_level]);
    res.json({ success: true });
});

// Get Curriculum (Filtered for Teachers)
app.get('/api/curriculum', authorize(), async (req, res) => {
    let query = `SELECT * FROM subjects`;
    let params = [];
    if (req.user.role === 'TEACHER') {
        query += ` WHERE id IN (SELECT subject_id FROM teacher_assignments WHERE user_id = $1)`;
        params = [req.user.id];
    }
    const data = await pool.query(query, params);
    res.json(data.rows);
});

app.listen(process.env.PORT || 3000);
