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

const JWT_SECRET = process.env.JWT_SECRET || 'YOUR_SECRET_KEY';

// --- AUTH ROUTE ---
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const userQuery = await pool.query('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username.trim()]);
        const user = userQuery.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }
        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token, role: user.role, name: user.full_name });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- STATE MANAGEMENT (PostgreSQL JSONB Implementation) ---
app.get('/api/admin/database-state', async (req, res) => {
    try {
        const result = await pool.query('SELECT data FROM system_state WHERE id = 1');
        res.json(result.rows.length > 0 ? result.rows[0].data : { classes: {}, teachers: [], students: {} });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/database-state', async (req, res) => {
    try {
        // Upsert the data into the JSONB column
        await pool.query(`
            INSERT INTO system_state (id, data) VALUES (1, $1) 
            ON CONFLICT (id) DO UPDATE SET data = $1`, [JSON.stringify(req.body)]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
