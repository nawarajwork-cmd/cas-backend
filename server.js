const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' })); // Update to your GitHub Pages URL for production

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'NEPAL_CAS_SYSTEM_CRYPT_KEY';

// --- MIDDLEWARE ---
const authorizeGateway = (req, res, next) => {
    const header = req.headers['authorization'];
    const token = header && header.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
        if (err) return res.status(403).json({ error: 'Session expired.' });
        req.user = decodedUser;
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') next();
    else res.status(403).json({ error: 'Access Denied: Admin only.' });
};

// --- AUTH ROUTE ---
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials.' });

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials.' });

        const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ token, role: user.role });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// --- ADMIN MANAGEMENT ROUTES (Checkpoint 2) ---
app.post('/api/admin/teachers', authorizeGateway, requireAdmin, async (req, res) => {
    try {
        const countRes = await pool.query('SELECT COUNT(*) FROM teachers');
        const nextIdNum = parseInt(countRes.rows[0].count) + 1;
        const newUsername = `T-${nextIdNum}`;
        const defaultPassword = '9876';

        await pool.query('INSERT INTO teachers (username, password) VALUES ($1, $2)', [newUsername, defaultPassword]);
        res.json({ success: true, teacher: { username: newUsername, password: defaultPassword } });
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/admin/assign', authorizeGateway, requireAdmin, async (req, res) => {
    const { teacher_id, subject_id } = req.body;
    try {
        await pool.query('INSERT INTO teacher_assignments (teacher_id, subject_id) VALUES ($1, $2)', [teacher_id, subject_id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Assignment failed' });
    }
});

// --- ADMIN DASHBOARD DATA (Checkpoint 2) ---
app.get('/api/admin/dashboard-data', authorizeGateway, requireAdmin, async (req, res) => {
    try {
        const teachers = await pool.query('SELECT * FROM teachers');
        const classes = await pool.query('SELECT * FROM classes');
        const subjects = await pool.query('SELECT * FROM subjects');
        const assignments = await pool.query(`
            SELECT ta.id, t.username as teacher_name, s.name as subject_name 
            FROM teacher_assignments ta
            JOIN teachers t ON ta.teacher_id = t.id
            JOIN subjects s ON ta.subject_id = s.id
        `);

        res.json({
            teachers: teachers.rows,
            classes: classes.rows,
            subjects: subjects.rows,
            assignments: assignments.rows
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch dashboard data' });
    }
});
// --- ANALYTICS ROUTE ---
app.get('/api/admin/analytics', authorizeGateway, requireAdmin, async (req, res) => {
    try {
        const stats = await pool.query(`
            SELECT 
                s.name as subject_name, 
                COUNT(m.id) as total_marks_recorded, 
                AVG(m.score) as average_score
            FROM subjects s
            LEFT JOIN marks m ON s.id = m.theme_id
            GROUP BY s.name
        `);
        res.json(stats.rows);
    } catch (err) {
        res.status(500).json({ error: 'Analytics fetch failed' });
    }
});

// --- EXISTING CORE ROUTES ---
app.post('/api/marks/save', authorizeGateway, async (req, res) => {
    const { student_id, theme_id, score } = req.body;
    try {
        if (score === null || score === '') {
            await pool.query('DELETE FROM marks WHERE student_id = $1 AND theme_id = $2', [student_id, theme_id]);
        } else {
            await pool.query(`
                INSERT INTO marks (student_id, theme_id, score) VALUES ($1, $2, $3)
                ON CONFLICT (student_id, theme_id) DO UPDATE SET score = EXCLUDED.score`, 
                [student_id, theme_id, score]
            );
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Internal server error' }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
