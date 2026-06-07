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
// ...if they are an ADMIN, they see everything; if they are a TEACHER, the query joins with the assignment table to restrict the results.
app.get('/api/curriculum', authorizeGateway, async (req, res) => {
    const { grade } = req.query;
    try {
        let query = `
            SELECT sub.id as subject_id, sub.subject_code, ch.id as chapter_id, ch.chapter_name, ch.is_active, th.id as theme_id, th.theme_name
            FROM subjects sub
            LEFT JOIN chapters ch ON ch.subject_id = sub.id
            LEFT JOIN themes th ON th.chapter_id = ch.id
            WHERE sub.grade_level = $1
        `;
        const params = [grade];

        // Apply filtering if the user is a teacher
        if (req.user.role === 'TEACHER') {
            query += ` AND sub.id IN (
                SELECT subject_id FROM teacher_assignments WHERE user_id = $2
            )`;
            params.push(req.user.id);
        }

        query += ` ORDER BY sub.subject_code, ch.sort_order, th.sort_order`;
        const data = await pool.query(query, params);
        res.json(data.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/assign-teacher', authorizeGateway, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Access Denied.' });
    
    const { user_id, subject_id, grade_level } = req.body;
    try {
        await pool.query(
            'INSERT INTO teacher_assignments (user_id, subject_id, grade_level) VALUES ($1, $2, $3)',
            [user_id, subject_id, grade_level]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Assignment failed: ' + err.message });
    }
});
app.listen(process.env.PORT || 3000);
