// backend/package.json dependency hints: "express", "pg", "bcryptjs", "jsonwebtoken", "cors"
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors({ origin: 'https://nawarajwork-cmd.github.io' })); // Configure explicitly to production GitHub Pages URL on live deploy

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET || 'NEPAL_CAS_CORE_ENGINE_CRYPT_KEY';

// --- AUTHENTICATION SHIELD MIDDLEWARE ---
const authorizeGateway = (req, res, next) => {
    const header = req.headers['authorization'];
    const token = header && header.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Session unauthorized. Login Required.' });

    jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
        if (err) return res.status(403).json({ error: 'Session expired or altered.' });
        req.user = decodedUser;
        next();
    });
};

// --- AUTH PROTOCOLS ---
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const userQuery = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = userQuery.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(400).json({ error: 'Invalid security verification metrics.' });
        }
        const token = jwt.sign({ id: user.id, role: user.role, name: user.full_name }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token, role: user.role, name: user.full_name });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- SCHOOL ADMINISTRATIVE PROFILE ENDPOINTS ---
app.get('/api/profile', authorizeGateway, async (req, res) => {
    try {
        const profile = await pool.query('SELECT * FROM school_profile WHERE id = 1');
        res.json(profile.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/profile', authorizeGateway, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(430).json({ error: 'Administrative clearance required.' });
    const { school_name, address_location, emis_code, selected_grade, academic_year, evaluation_term } = req.body;
    try {
        await pool.query(`
            UPDATE school_profile SET 
                school_name = $1, address_location = $2, emis_code = $3, 
                selected_grade = $4, academic_year = $5, evaluation_term = $6 
            WHERE id = 1`, 
            [school_name, address_location, emis_code, selected_grade, academic_year, evaluation_term]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- CURRICULUM ARCHITECTURE PIPELINES ---
app.get('/api/curriculum', authorizeGateway, async (req, res) => {
    const { grade } = req.query;
    try {
        let sql = `
            SELECT sub.id as subject_id, sub.subject_code, ch.id as chapter_id, ch.chapter_name, ch.is_active, th.id as theme_id, th.theme_name
            FROM subjects sub
            LEFT JOIN chapters ch ON ch.subject_id = sub.id
            LEFT JOIN themes th ON th.chapter_id = ch.id
            WHERE sub.grade_level = $1
        `;
        let params = [grade];

        if (req.user.role === 'TEACHER') {
            sql += ` AND sub.id IN (SELECT subject_id FROM teacher_assignments WHERE user_id = $2)`;
            params.push(req.user.id);
        }
        
        sql += ` ORDER BY sub.subject_code, ch.sort_order, th.sort_order`;
        const data = await pool.query(sql, params);
        res.json(data.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin Control: Add Subject Structure
app.post('/api/curriculum/subject', authorizeGateway, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Access denied.' });
    const { subject_code, grade_level } = req.body;
    try {
        const result = await pool.query('INSERT INTO subjects (subject_code, grade_level) VALUES ($1, $2) RETURNING *', [subject_code, grade_level]);
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin Control: Append Chapter
app.post('/api/curriculum/chapter', authorizeGateway, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Access denied.' });
    const { subject_id, chapter_name } = req.body;
    try {
        const result = await pool.query('INSERT INTO chapters (subject_id, chapter_name) VALUES ($1, $2) RETURNING *', [subject_id, chapter_name]);
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin Control: Append Theme Module 
app.post('/api/curriculum/theme', authorizeGateway, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Access denied.' });
    const { chapter_id, theme_name } = req.body;
    try {
        const result = await pool.query('INSERT INTO themes (chapter_id, theme_name) VALUES ($1, $2) RETURNING *', [chapter_id, theme_name]);
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Dynamic Toggle for Chapter Status
app.put('/api/curriculum/chapter/:id/toggle', authorizeGateway, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Access denied.' });
    const { is_active } = req.body;
    try {
        await pool.query('UPDATE chapters SET is_active = $1 WHERE id = $2', [is_active, req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Generic Delete Components for Administrators
app.delete('/api/curriculum/:type/:id', authorizeGateway, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Access denied.' });
    const tableMap = { 'subject': 'subjects', 'chapter': 'chapters', 'theme': 'themes' };
    const table = tableMap[req.params.type];
    if (!table) return res.status(400).json({ error: 'Invalid operation routing entity.' });
    try {
        await pool.query(`DELETE FROM ${table} WHERE id = $1`, [req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- ROSTER LEDGER REGISTRATIONS ---
app.get('/api/students', authorizeGateway, async (req, res) => {
    const { grade } = req.query;
    try {
        const ledger = await pool.query('SELECT * FROM students WHERE grade_level = $1 ORDER BY roll_number', [grade]);
        const marks = await pool.query(`
            SELECT m.student_id, m.theme_id, m.score FROM marks m 
            JOIN students s ON s.id = m.student_id WHERE s.grade_level = $1`, [grade]);
        res.json({ students: ledger.rows, marks: marks.rows });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/students/bulk', authorizeGateway, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Access denied.' });
    const { grade, names } = req.body;
    try {
        const baseRollResult = await pool.query('SELECT COALESCE(MAX(roll_number), 0) as max_roll FROM students WHERE grade_level = $1', [grade]);
        let currentRoll = parseInt(baseRollResult.rows[0].max_roll);

        for (let name of names) {
            currentRoll++;
            await pool.query('INSERT INTO students (grade_level, student_name, roll_number) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [grade, name, currentRoll]);
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/students/:id', authorizeGateway, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Access denied.' });
    try {
        await pool.query('DELETE FROM students WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- SUBMIT COMPILATION SCORE LEDGER TRANSACTIONS ---
app.post('/api/marks/save', authorizeGateway, async (req, res) => {
    const { student_id, theme_id, score } = req.body;
    try {
        if (req.user.role === 'TEACHER') {
            const permissionVerify = await pool.query(`
                SELECT 1 FROM teacher_assignments ta
                JOIN subjects sub ON sub.id = ta.subject_id
                JOIN chapters ch ON ch.subject_id = sub.id
                JOIN themes th ON th.chapter_id = ch.id
                WHERE ta.user_id = $1 AND th.id = $2`, [req.user.id, theme_id]);
            if (permissionVerify.rowCount === 0) return res.status(403).json({ error: 'Unauthorized subject channel mapping routing access context configuration verification failure.' });
        }

        if (score === null || score === '') {
            await pool.query('DELETE FROM marks WHERE student_id = $1 AND theme_id = $2', [student_id, theme_id]);
        } else {
            await pool.query(`
                INSERT INTO marks (student_id, theme_id, score, updated_by_user_id, updated_at)
                VALUES ($1, $2, $3, $4, NOW())
                ON CONFLICT (student_id, theme_id) DO UPDATE 
                SET score = EXCLUDED.score, updated_by_user_id = EXCLUDED.updated_by_user_id, updated_at = NOW()`,
                [student_id, theme_id, score, req.user.id]
            );
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`CAS Ledger Engine Operational Infrastructure listening on Port: ${PORT}`));