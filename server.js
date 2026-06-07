	const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware parsing rules
app.use(express.json());
app.use(cors({ origin: 'https://nawarajwork-cmd.github.io' })); // Replace with your exact GitHub pages URL when live

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'NEPAL_CAS_SYSTEM_CRYPT_KEY';

// --- AUTHENTICATION SHIELD MIDDLEWARE ---
const authorizeGateway = (req, res, next) => {
    const header = req.headers['authorization'];
    const token = header && header.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Session unauthorized. Access Denied.' });
	// --- ROLE-BASED ACCESS GATEWAY ---
const requireAdmin = (req, res, next) => {
    // req.user is populated by authorizeGateway
    if (req.user && req.user.role === 'admin') {
        next(); // Proceed if admin
    } else {
        res.status(403).json({ error: 'Access Denied: Admin only.' });
    }
};
    jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
        if (err) return res.status(403).json({ error: 'Session expired.' });
        req.user = decodedUser;
        next();
    });
};


app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Missing username or password fields.' });
    }

    try {
        // Query the database to find the user
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        // Generate JWT with role
        const token = jwt.sign(
            { username: user.username, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '8h' }
        );

        res.json({ token, role: user.role });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

//--- AUTH ROUTE WITH SYSTEM VALIDATION FIX ---
 /*app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Missing username or password fields.' });
    }

    try {
        // ========================================================
        // EMERGENCY PROGRAMMATIC RESET SEED (Bypasses pgAdmin)
        // This generates a brand new local hash and forces it live
        if (username.trim().toLowerCase() === 'admin') {
            console.log("System triggering programmatic credential synchronization reset...");
            const nativeFreshHash = await bcrypt.hash('Admin123', 10);
           
            await pool.query(`
                INSERT INTO users (username, password_hash, full_name, role) 
                VALUES ('admin', $1, 'System Administrator', 'ADMIN');
            `, [nativeFreshHash]);
            console.log("Programmatic database reset execution successful.");
        }
        // ========================================================
        
        // Run standard login verification routine
        const userQuery = await pool.query('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username.trim()]);
        const user = userQuery.rows[0];
        
        if (!user) {
            return res.status(400).json({ error: `Database check failed: Username '${username}' does not exist in the table.` });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Database check failed: Password hash encryption mismatch.' });
        }*/

// Inside your login route, after verifying the password:
// Ensure your database query fetched the 'role' column from the users table
// REPLACE your existing jwt.sign block with this:
const token = jwt.sign(
    { 
        username: user.username, 
        role: user.role // Include the role from the DB record here
    }, 
    JWT_SECRET, 
    { expiresIn: '8h' }
);
res.json({ token, role: user.role }); // Send the role to the frontend
    } catch (err) {
        res.status(400).json({ error: `Database Engine Crash: ${err.message}` });
    }
});


// --- ENGINE PROFILE ENDPOINTS ---
app.get('/api/profile', authorizeGateway, async (req, res) => {
    try {
        const profile = await pool.query('SELECT * FROM school_profile WHERE id = 1');
        res.json(profile.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/profile', authorizeGateway, async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Administrative clearance required.' });
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
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- CURRICULUM MANAGEMENT ENDPOINTS ---
app.get('/api/curriculum', authorizeGateway, async (req, res) => {
    const { grade } = req.query;
    try {
        const data = await pool.query(`
            SELECT sub.id as subject_id, sub.subject_code, ch.id as chapter_id, ch.chapter_name, ch.is_active, th.id as theme_id, th.theme_name
            FROM subjects sub
            LEFT JOIN chapters ch ON ch.subject_id = sub.id
            LEFT JOIN themes th ON th.chapter_id = ch.id
            WHERE sub.grade_level = $1
            ORDER BY sub.subject_code, ch.sort_order, th.sort_order`, [grade]);
        res.json(data.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/curriculum/subject', authorizeGateway, async (req, res) => {
    const { subject_code, grade_level } = req.body;
    try {
        const r = await pool.query('INSERT INTO subjects (subject_code, grade_level) VALUES ($1, $2) RETURNING *', [subject_code, grade_level]);
        res.json(r.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/curriculum/chapter', authorizeGateway, async (req, res) => {
    const { subject_id, chapter_name } = req.body;
    try {
        const r = await pool.query('INSERT INTO chapters (subject_id, chapter_name) VALUES ($1, $2) RETURNING *', [subject_id, chapter_name]);
        res.json(r.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/curriculum/theme', authorizeGateway, async (req, res) => {
    const { chapter_id, theme_name } = req.body;
    try {
        const r = await pool.query('INSERT INTO themes (chapter_id, theme_name) VALUES ($1, $2) RETURNING *', [chapter_id, theme_name]);
        res.json(r.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/curriculum/chapter/:id/toggle', authorizeGateway, async (req, res) => {
    const { is_active } = req.body;
    try {
        await pool.query('UPDATE chapters SET is_active = $1 WHERE id = $2', [is_active, req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/curriculum/:type/:id', authorizeGateway, async (req, res) => {
    const tMap = { 'subject': 'subjects', 'chapter': 'chapters', 'theme': 'themes' };
    try {
        await pool.query(`DELETE FROM ${tMap[req.params.type]} WHERE id = $1`, [req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- MARKS & STUDENT REGISTER RECORD PIPELINES ---
app.get('/api/students', authorizeGateway, async (req, res) => {
    const { grade } = req.query;
    try {
        const st = await pool.query('SELECT * FROM students WHERE grade_level = $1 ORDER BY roll_number', [grade]);
        const mk = await pool.query(`
            SELECT m.student_id, m.theme_id, m.score FROM marks m 
            JOIN students s ON s.id = m.student_id WHERE s.grade_level = $1`, [grade]);
        res.json({ students: st.rows, marks: mk.rows });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/students/bulk', authorizeGateway, async (req, res) => {
    const { grade, names } = req.body;
    try {
        const mxRoll = await pool.query('SELECT COALESCE(MAX(roll_number), 0) as max_roll FROM students WHERE grade_level = $1', [grade]);
        let nextRoll = parseInt(mxRoll.rows[0].max_roll);

        for (let name of names) {
            nextRoll++;
            await pool.query('INSERT INTO students (grade_level, student_name, roll_number) VALUES ($1, $2, $3)', [grade, name, nextRoll]);
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/students/:id', authorizeGateway, async (req, res) => {
    try {
        await pool.query('DELETE FROM students WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/marks/save', authorizeGateway, async (req, res) => {
    const { student_id, theme_id, score } = req.body;
    try {
        if (score === null || score === '') {
            await pool.query('DELETE FROM marks WHERE student_id = $1 AND theme_id = $2', [student_id, theme_id]);
        } else {
            await pool.query(`
                INSERT INTO marks (student_id, theme_id, score) VALUES ($1, $2, $3)
                ON CONFLICT (student_id, theme_id) DO UPDATE SET score = EXCLUDED.score`, [student_id, theme_id, score]);
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
// --- ADMIN MANAGEMENT ROUTES (Checkpoint 2) ---

// 1. Create Teacher (Auto-generates T-1, T-2 IDs)
app.post('/api/admin/teachers', authorizeGateway, async (req, res) => {
    // Check if requester is admin
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access Denied' });

    try {
        // Count existing teachers to generate sequential ID
        const countRes = await pool.query('SELECT COUNT(*) FROM teachers');
        const nextIdNum = parseInt(countRes.rows[0].count) + 1;
        const newUsername = `T-${nextIdNum}`;
        const defaultPassword = '9876';

        await pool.query(
            'INSERT INTO teachers (username, password) VALUES ($1, $2)',
            [newUsername, defaultPassword]
        );

        res.json({ success: true, teacher: { username: newUsername, password: defaultPassword } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 2. Assign Subject to Teacher (Bridge Logic)
app.post('/api/admin/assign', authorizeGateway, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access Denied' });
    
    const { teacher_id, subject_id } = req.body;
    try {
        await pool.query(
            'INSERT INTO teacher_assignments (teacher_id, subject_id) VALUES ($1, $2)', 
            [teacher_id, subject_id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Assignment failed' });
    }
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server executing safely on port ${PORT}`));
