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

// --- HELPERS: SQL State Management ---
const getFullState = async () => {
    const res = await pool.query('SELECT data FROM system_state WHERE id = 1');
    return res.rows.length > 0 ? res.rows[0].data : { classes: {}, teachers: [], students: {} };
};

const saveFullState = async (state) => {
    await pool.query(`
        INSERT INTO system_state (id, data) VALUES (1, $1) 
        ON CONFLICT (id) DO UPDATE SET data = $1`, [JSON.stringify(state)]);
};

// --- ROUTES ---
app.get('/api/admin/database-state', async (req, res) => {
    try { res.json(await getFullState()); } 
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/database-state', async (req, res) => {
    try { await saveFullState(req.body); res.json({ success: true }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/classes', async (req, res) => {
    try {
        const { className } = req.body;
        let state = await getFullState();
        if (state.classes[className]) return res.status(400).json({ error: "Class exists." });
        state.classes[className] = { subjects: {} };
        await saveFullState(state);
        res.json({ success: true, state });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/teachers', async (req, res) => {
    try {
        const { name } = req.body;
        let state = await getFullState();
        const newTeacher = { id: `teacher.${state.teachers.length + 1}`, name, pass: "9876", assignments: [] };
        state.teachers.push(newTeacher);
        await saveFullState(state);
        res.json({ success: true, state });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ... (Follow this pattern to replace all other 'State' calls with getFullState/saveFullState)

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server executing safely on port ${PORT}`));
