const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'NEPAL_CAS_SYSTEM_CRYPT_KEY';

// --- AUTHENTICATION SHIELD ---
const authorizeGateway = (req, res, next) => {
    const header = req.headers['authorization'];
    const token = header && header.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Session unauthorized.' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Session expired.' });
        req.user = decoded;
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
            return res.status(400).json({ error: 'Invalid credentials.' });
        }
        const token = jwt.sign({ id: user.id, role: user.role, name: user.full_name }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token, role: user.role, name: user.full_name });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- STATE MANAGEMENT (Replaced Mongoose with SQL) ---
// Note: Since you use PostgreSQL, "State" should be stored in a 'system_state' table.
// If you haven't created it, run: CREATE TABLE system_state (id SERIAL PRIMARY KEY, data JSONB);

app.get('/api/admin/database-state', async (req, res) => {
    try {
        const result = await pool.query('SELECT data FROM system_state WHERE id = 1');
        res.json(result.rows.length > 0 ? result.rows[0].data : { classes: {}, teachers: [], students: {} });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/database-state', async (req, res) => {
    try {
        const data = JSON.stringify(req.body);
        await pool.query(`
            INSERT INTO system_state (id, data) VALUES (1, $1) 
            ON CONFLICT (id) DO UPDATE SET data = $1`, [data]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- TEACHER CRUD (Example of mapping your logic to SQL) ---
app.post('/api/admin/teachers', async (req, res) => {
    try {
        const { name } = req.body;
        // Logic: Get current state, update it, save it back
        const result = await pool.query('SELECT data FROM system_state WHERE id = 1');
        let state = result.rows.length > 0 ? result.rows[0].data : { teachers: [] };
        
        const newTeacher = { id: `teacher.${state.teachers.length + 1}`, name, pass: "9876", assignments: [] };
        state.teachers.push(newTeacher);

        await pool.query('UPDATE system_state SET data = $1 WHERE id = 1', [JSON.stringify(state)]);
        res.json({ success: true, state });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- KEEP YOUR EXISTING SCHOOL PROFILE/CURRICULUM ROUTES HERE ---

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
