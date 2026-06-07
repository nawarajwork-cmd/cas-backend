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

// --- SQL STATE HELPERS ---
const getFullState = async () => {
    const res = await pool.query('SELECT data FROM system_state WHERE id = 1');
    return res.rows.length > 0 ? res.rows[0].data : { classes: {}, teachers: [], students: {} };
};

const saveFullState = async (state) => {
    await pool.query(`
        INSERT INTO system_state (id, data) VALUES (1, $1) 
        ON CONFLICT (id) DO UPDATE SET data = $1`, [JSON.stringify(state)]);
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
        const token = jwt.sign({ id: user.id, role: user.role, name: user.full_name }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token, role: user.role, name: user.full_name });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- ADMIN CRUD ROUTES ---
app.get('/api/admin/database-state', async (req, res) => {
    try { res.json(await getFullState()); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/database-state', async (req, res) => {
    try { await saveFullState(req.body); res.json({ success: true }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/teachers', async (req, res) => {
    try {
        const { name } = req.body;
        let state = await getFullState();
        state.teachers.push({ id: `teacher.${state.teachers.length + 1}`, name, pass: "9876", assignments: [] });
        await saveFullState(state);
        res.json({ success: true, state });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
