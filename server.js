const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'NEPAL_CAS_SYSTEM_CRYPT_KEY';

// Middleware
const authorizeGateway = (req, res, next) => {
    const header = req.headers['authorization'];
    const token = header && header.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Expired' });
        req.user = decoded;
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') next();
    else res.status(403).json({ error: 'Admin only' });
};

// Auth
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0 || result.rows[0].password !== password) return res.status(401).json({ error: 'Invalid' });
    const token = jwt.sign({ username: username, role: result.rows[0].role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, role: result.rows[0].role });
});

// Admin Routes
app.post('/api/admin/teachers', authorizeGateway, requireAdmin, async (req, res) => {
    const countRes = await pool.query('SELECT COUNT(*) FROM teachers');
    const newUsername = `T-${parseInt(countRes.rows[0].count) + 1}`;
    await pool.query('INSERT INTO teachers (username, password) VALUES ($1, $2)', [newUsername, '9876']);
    res.json({ success: true, teacher: { username: newUsername, password: '9876' } });
});

app.post('/api/admin/assign', authorizeGateway, requireAdmin, async (req, res) => {
    const { teacher_id, subject_id } = req.body;
    await pool.query('INSERT INTO teacher_assignments (teacher_id, subject_id) VALUES ($1, $2)', [teacher_id, subject_id]);
    res.json({ success: true });
});

app.get('/api/admin/dashboard-data', authorizeGateway, requireAdmin, async (req, res) => {
    const teachers = await pool.query('SELECT * FROM teachers');
    const subjects = await pool.query('SELECT * FROM subjects');
    const assignments = await pool.query('SELECT t.username, s.name FROM teacher_assignments ta JOIN teachers t ON ta.teacher_id = t.id JOIN subjects s ON ta.subject_id = s.id');
    res.json({ teachers: teachers.rows, subjects: subjects.rows, assignments: assignments.rows });
});

app.listen(process.env.PORT || 3000);
