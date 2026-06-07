const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const JWT_SECRET = process.env.JWT_SECRET || 'NEPAL_CAS_SYSTEM_CRYPT_KEY';

// --- AUTHENTICATION & RBAC MIDDLEWARE ---
const authorize = (role) => (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || (role && decoded.role !== role)) return res.status(403).json({ error: 'Forbidden' });
        req.user = decoded;
        next();
    });
};

// --- AUTH ROUTE ---
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = (await pool.query('SELECT * FROM users WHERE username = $1', [username])).rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) 
        return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, role: user.role });
});

// --- ADMIN: TEACHER MANAGEMENT ---
app.post('/api/admin/teachers', authorize('ADMIN'), async (req, res) => {
    const { name } = req.body;
    const count = (await pool.query('SELECT COUNT(*) FROM users WHERE role = $1', ['TEACHER'])).rows[0].count;
    const username = `e${parseInt(count) + 1}`;
    const hash = await bcrypt.hash('9876', 10);
    await pool.query('INSERT INTO users (username, password_hash, full_name, role) VALUES ($1, $2, $3, $4)', [username, hash, name, 'TEACHER']);
    res.json({ username, password: '9876' });
});

app.post('/api/admin/assign', authorize('ADMIN'), async (req, res) => {
    const { user_id, subject_id } = req.body;
    await pool.query('INSERT INTO teacher_assignments (user_id, subject_id) VALUES ($1, $2)', [user_id, subject_id]);
    res.json({ success: true });
});

// --- CURRICULUM CRUD ---
app.get('/api/curriculum', authorize(), async (req, res) => {
    // Teachers only see assigned subjects
    const query = req.user.role === 'ADMIN' 
        ? `SELECT * FROM curriculum_view` 
        : `SELECT * FROM curriculum_view WHERE subject_id IN (SELECT subject_id FROM teacher_assignments WHERE user_id = ${req.user.id})`;
    const data = await pool.query(query);
    res.json(data.rows);
});

// ... [Include your other CRUD endpoints here, wrapped in authorize('ADMIN')]

app.listen(process.env.PORT || 3000);
