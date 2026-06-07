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

// --- SQL HELPER FUNCTIONS ---
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
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Missing credentials.' });
    }

    try {
        // Query the 'users' table in PostgreSQL
        const userQuery = await pool.query(
            'SELECT * FROM users WHERE LOWER(username) = LOWER($1)', 
            [username.trim()]
        );
        
        const user = userQuery.rows[0];
        
        // Check if user exists and compare password hash
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: 'Invalid node credentials.' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, role: user.role, name: user.full_name }, 
            JWT_SECRET, 
            { expiresIn: '12h' }
        );
        
        res.json({ token, role: user.role, name: user.full_name });
    } catch (err) { 
        res.status(500).json({ error: 'Database connection error: ' + err.message }); 
    }
});

// --- ADMIN STATE ROUTES ---
app.get('/api/admin/database-state', async (req, res) => {
    try { res.json(await getFullState()); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/database-state', async (req, res) => {
    try { await saveFullState(req.body); res.json({ success: true }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- REMAINING CRUD ROUTES ---
app.post('/api/admin/classes', async (req, res) => {
    try {
        const { className } = req.body;
        let state = await getFullState();
        if (state.classes[className]) return res.status(400).json({ error: "Class already exists." });
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
// 4. CREATE SUBJECT
app.post('/api/admin/subjects', async (req, res) => {
    try {
        const { className, subjectName } = req.body;
        let state = await getFullState();
        if (!state.classes[className]) return res.status(404).json({ error: "Class not found." });
        state.classes[className].subjects[subjectName.trim().toUpperCase()] = [];
        await saveFullState(state);
        res.json({ success: true, state });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 6. UPDATE TEACHER
app.put('/api/admin/teachers/:id', async (req, res) => {
    try {
        const { name, pass } = req.body;
        let state = await getFullState();
        let teacher = state.teachers.find(t => t.id === req.params.id);
        if (!teacher) return res.status(404).json({ error: "Teacher not found." });
        if (name) teacher.name = name.trim();
        if (pass) teacher.pass = pass.trim();
        await saveFullState(state);
        res.json({ success: true, state });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 7. ASSIGN TEACHER
app.post('/api/admin/assignments', async (req, res) => {
    try {
        const { teacherId, className, subjectName } = req.body;
        let state = await getFullState();
        let teacher = state.teachers.find(t => t.id === teacherId);
        if (!teacher) return res.status(404).json({ error: "Teacher not found." });
        teacher.assignments.push({ class: className, subject: subjectName });
        await saveFullState(state);
        res.json({ success: true, state });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 9. DELETE TEACHER
app.delete('/api/admin/teachers/:id', async (req, res) => {
    try {
        let state = await getFullState();
        state.teachers = state.teachers.filter(t => t.id !== req.params.id);
        await saveFullState(state);
        res.json({ success: true, state });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
// ... (Follow this pattern to replace all other 'State' calls with getFullState/saveFullState)

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server executing safely on port ${PORT}`));
