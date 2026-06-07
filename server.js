const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json());

app.use(cors({
    origin: ' https://nawarajwork-cmd.github.io',
    credentials: true
}));

// ================= DATABASE =================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

const JWT_SECRET =
    process.env.JWT_SECRET ||
    'SIRJANA_CAS_SECRET_KEY';

// ================= DATABASE INITIALIZER =================

async function initializeDatabase() {

    // USERS
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name VARCHAR(120),
            role VARCHAR(20) NOT NULL DEFAULT 'TEACHER',
            created_at TIMESTAMP DEFAULT NOW()
        );
    `);

    // SCHOOL PROFILE
    await pool.query(`
        CREATE TABLE IF NOT EXISTS school_profile (
            id SERIAL PRIMARY KEY,
            school_name TEXT,
            address_location TEXT,
            emis_code TEXT,
            selected_grade TEXT,
            academic_year TEXT,
            evaluation_term TEXT
        );
    `);

    // CREATE DEFAULT PROFILE ROW
    const profileCheck =
        await pool.query(
            'SELECT * FROM school_profile WHERE id = 1'
        );

    if(profileCheck.rows.length === 0) {

        await pool.query(`
            INSERT INTO school_profile
            (
                id,
                school_name,
                address_location,
                emis_code,
                selected_grade,
                academic_year,
                evaluation_term
            )
            VALUES
            (
                1,
                '',
                '',
                '',
                '1',
                '',
                ''
            )
        `);
    }

    // SUBJECTS
    await pool.query(`
        CREATE TABLE IF NOT EXISTS subjects (
            id SERIAL PRIMARY KEY,
            subject_code VARCHAR(100) NOT NULL,
            grade_level VARCHAR(20) NOT NULL
        );
    `);

    // CHAPTERS
    await pool.query(`
        CREATE TABLE IF NOT EXISTS chapters (
            id SERIAL PRIMARY KEY,
            subject_id INTEGER REFERENCES subjects(id)
            ON DELETE CASCADE,
            chapter_name TEXT NOT NULL,
            is_active BOOLEAN DEFAULT true,
            sort_order INTEGER DEFAULT 0
        );
    `);

    // THEMES
    await pool.query(`
        CREATE TABLE IF NOT EXISTS themes (
            id SERIAL PRIMARY KEY,
            chapter_id INTEGER REFERENCES chapters(id)
            ON DELETE CASCADE,
            theme_name TEXT NOT NULL,
            sort_order INTEGER DEFAULT 0
        );
    `);

    // STUDENTS
    await pool.query(`
        CREATE TABLE IF NOT EXISTS students (
            id SERIAL PRIMARY KEY,
            grade_level VARCHAR(20),
            student_name TEXT NOT NULL,
            roll_number INTEGER
        );
    `);

    // MARKS
    await pool.query(`
        CREATE TABLE IF NOT EXISTS marks (
            id SERIAL PRIMARY KEY,
            student_id INTEGER REFERENCES students(id)
            ON DELETE CASCADE,
            theme_id INTEGER REFERENCES themes(id)
            ON DELETE CASCADE,
            score NUMERIC(4,2),

            UNIQUE(student_id, theme_id)
        );
    `);

    // TEACHER ASSIGNMENTS
    await pool.query(`
        CREATE TABLE IF NOT EXISTS teacher_subject_assignments (
            id SERIAL PRIMARY KEY,

            teacher_id INTEGER
            REFERENCES users(id)
            ON DELETE CASCADE,

            subject_id INTEGER
            REFERENCES subjects(id)
            ON DELETE CASCADE,

            grade_level VARCHAR(20) NOT NULL
        );
    `);

    // DEFAULT ADMIN
    const adminCheck =
        await pool.query(`
            SELECT * FROM users
            WHERE username = 'admin'
        `);

    if(adminCheck.rows.length === 0) {

        const hash =
            await bcrypt.hash('Admin123', 10);

        await pool.query(`
            INSERT INTO users
            (
                username,
                password_hash,
                full_name,
                role
            )
            VALUES
            (
                'admin',
                $1,
                'System Administrator',
                'ADMIN'
            )
        `, [hash]);

        console.log('Default admin created');
    }

    console.log('Database initialized');
}

// ================= AUTH MIDDLEWARE =================

const authorizeGateway =
(req, res, next) => {

    const header =
        req.headers['authorization'];

    const token =
        header && header.split(' ')[1];

    if(!token) {

        return res.status(401).json({
            error: 'Unauthorized'
        });
    }

    jwt.verify(
        token,
        JWT_SECRET,
        (err, decoded) => {

            if(err) {

                return res.status(403).json({
                    error: 'Session expired'
                });
            }

            req.user = decoded;

            next();
        }
    );
};

// ================= LOGIN =================

app.post('/api/auth/login',
async (req, res) => {

    const {
        username,
        password
    } = req.body;

    try {

        const userQuery =
            await pool.query(`
                SELECT *
                FROM users
                WHERE LOWER(username)
                = LOWER($1)
            `, [username]);

        const user =
            userQuery.rows[0];

        if(!user) {

            return res.status(400).json({
                error: 'User not found'
            });
        }

        const valid =
            await bcrypt.compare(
                password,
                user.password_hash
            );

        if(!valid) {

            return res.status(400).json({
                error: 'Invalid password'
            });
        }

        const token = jwt.sign(
            {
                id: user.id,
                role: user.role,
                name: user.full_name
            },
            JWT_SECRET,
            {
                expiresIn: '12h'
            }
        );

        res.json({
            token,
            role: user.role,
            name: user.full_name
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// ================= PROFILE =================

app.get('/api/profile',
authorizeGateway,
async (req, res) => {

    try {

        const profile =
            await pool.query(`
                SELECT *
                FROM school_profile
                WHERE id = 1
            `);

        res.json(profile.rows[0]);

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

app.post('/api/profile',
authorizeGateway,
async (req, res) => {

    if(req.user.role !== 'ADMIN') {

        return res.status(403).json({
            error: 'Admin only'
        });
    }

    const {
        school_name,
        address_location,
        emis_code,
        selected_grade,
        academic_year,
        evaluation_term
    } = req.body;

    try {

        await pool.query(`
            UPDATE school_profile
            SET
                school_name = $1,
                address_location = $2,
                emis_code = $3,
                selected_grade = $4,
                academic_year = $5,
                evaluation_term = $6
            WHERE id = 1
        `, [
            school_name,
            address_location,
            emis_code,
            selected_grade,
            academic_year,
            evaluation_term
        ]);

        res.json({
            success: true
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// ================= TEACHER CRUD =================

// CREATE TEACHER
app.post('/api/admin/teachers',
authorizeGateway,
async (req, res) => {

    if(req.user.role !== 'ADMIN') {

        return res.status(403).json({
            error: 'Admin only'
        });
    }

    const { full_name } = req.body;

    try {

        const count =
            await pool.query(`
                SELECT COUNT(*)
                FROM users
                WHERE role = 'TEACHER'
            `);

        const serial =
            parseInt(count.rows[0].count) + 1;

        const username = `T${serial}`;

        const password = '9876';

        const hash =
            await bcrypt.hash(password, 10);

        const result =
            await pool.query(`
                INSERT INTO users
                (
                    username,
                    password_hash,
                    full_name,
                    role
                )
                VALUES
                (
                    $1,
                    $2,
                    $3,
                    'TEACHER'
                )
                RETURNING
                id,
                username,
                full_name,
                role
            `, [
                username,
                hash,
                full_name
            ]);

        res.json({
            teacher: result.rows[0],
            password
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// GET TEACHERS
app.get('/api/admin/teachers',
authorizeGateway,
async (req, res) => {

    if(req.user.role !== 'ADMIN') {

        return res.status(403).json({
            error: 'Admin only'
        });
    }

    try {

        const teachers =
            await pool.query(`
                SELECT
                    id,
                    username,
                    full_name,
                    role
                FROM users
                WHERE role = 'TEACHER'
                ORDER BY id
            `);

        res.json(teachers.rows);

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// UPDATE TEACHER
app.put('/api/admin/teachers/:id',
authorizeGateway,
async (req, res) => {

    if(req.user.role !== 'ADMIN') {

        return res.status(403).json({
            error: 'Admin only'
        });
    }

    const {
        username,
        full_name
    } = req.body;

    try {

        await pool.query(`
            UPDATE users
            SET
                username = $1,
                full_name = $2
            WHERE id = $3
        `, [
            username,
            full_name,
            req.params.id
        ]);

        res.json({
            success: true
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// DELETE TEACHER
app.delete('/api/admin/teachers/:id',
authorizeGateway,
async (req, res) => {

    if(req.user.role !== 'ADMIN') {

        return res.status(403).json({
            error: 'Admin only'
        });
    }

    try {

        await pool.query(`
            DELETE FROM users
            WHERE id = $1
        `, [req.params.id]);

        res.json({
            success: true
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// ================= SUBJECTS =================

app.get('/api/subjects',
authorizeGateway,
async (req, res) => {

    try {

        let query;
        let params = [];

        if(req.user.role === 'ADMIN') {

            query = `
                SELECT *
                FROM subjects
                ORDER BY grade_level, subject_code
            `;

        } else {

            query = `
                SELECT DISTINCT
                    s.*
                FROM subjects s
                JOIN teacher_subject_assignments tsa
                ON tsa.subject_id = s.id
                WHERE tsa.teacher_id = $1
                ORDER BY s.grade_level, s.subject_code
            `;

            params = [req.user.id];
        }

        const result =
            await pool.query(query, params);

        res.json(result.rows);

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// CREATE SUBJECT
app.post('/api/curriculum/subject',
authorizeGateway,
async (req, res) => {

    if(req.user.role !== 'ADMIN') {

        return res.status(403).json({
            error: 'Admin only'
        });
    }

    const {
        subject_code,
        grade_level
    } = req.body;

    try {

        const result =
            await pool.query(`
                INSERT INTO subjects
                (
                    subject_code,
                    grade_level
                )
                VALUES
                (
                    $1,
                    $2
                )
                RETURNING *
            `, [
                subject_code,
                grade_level
            ]);

        res.json(result.rows[0]);

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// ================= TEACHER ASSIGNMENT =================

app.post('/api/admin/assign-teacher',
authorizeGateway,
async (req, res) => {

    if(req.user.role !== 'ADMIN') {

        return res.status(403).json({
            error: 'Admin only'
        });
    }

    const {
        teacher_id,
        subject_id,
        grade_level
    } = req.body;

    try {

        await pool.query(`
            INSERT INTO
            teacher_subject_assignments
            (
                teacher_id,
                subject_id,
                grade_level
            )
            VALUES
            (
                $1,
                $2,
                $3
            )
        `, [
            teacher_id,
            subject_id,
            grade_level
        ]);

        res.json({
            success: true
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// ================= CURRICULUM =================

app.get('/api/curriculum',
authorizeGateway,
async (req, res) => {

    const { grade } = req.query;

    try {

        let query;
        let params;

        if(req.user.role === 'ADMIN') {

            query = `
                SELECT
                    sub.id as subject_id,
                    sub.subject_code,
                    ch.id as chapter_id,
                    ch.chapter_name,
                    ch.is_active,
                    th.id as theme_id,
                    th.theme_name

                FROM subjects sub

                LEFT JOIN chapters ch
                ON ch.subject_id = sub.id

                LEFT JOIN themes th
                ON th.chapter_id = ch.id

                WHERE sub.grade_level = $1

                ORDER BY
                    sub.subject_code,
                    ch.sort_order,
                    th.sort_order
            `;

            params = [grade];

        } else {

            query = `
                SELECT
                    sub.id as subject_id,
                    sub.subject_code,
                    ch.id as chapter_id,
                    ch.chapter_name,
                    ch.is_active,
                    th.id as theme_id,
                    th.theme_name

                FROM teacher_subject_assignments tsa

                JOIN subjects sub
                ON sub.id = tsa.subject_id

                LEFT JOIN chapters ch
                ON ch.subject_id = sub.id

                LEFT JOIN themes th
                ON th.chapter_id = ch.id

                WHERE
                    tsa.teacher_id = $1
                    AND sub.grade_level = $2

                ORDER BY
                    sub.subject_code,
                    ch.sort_order,
                    th.sort_order
            `;

            params = [
                req.user.id,
                grade
            ];
        }

        const result =
            await pool.query(query, params);

        res.json(result.rows);

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// CREATE CHAPTER
app.post('/api/curriculum/chapter',
authorizeGateway,
async (req, res) => {

    const {
        subject_id,
        chapter_name
    } = req.body;

    try {

        await pool.query(`
            INSERT INTO chapters
            (
                subject_id,
                chapter_name
            )
            VALUES
            (
                $1,
                $2
            )
        `, [
            subject_id,
            chapter_name
        ]);

        res.json({
            success: true
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// CREATE THEME
app.post('/api/curriculum/theme',
authorizeGateway,
async (req, res) => {

    const {
        chapter_id,
        theme_name
    } = req.body;

    try {

        await pool.query(`
            INSERT INTO themes
            (
                chapter_id,
                theme_name
            )
            VALUES
            (
                $1,
                $2
            )
        `, [
            chapter_id,
            theme_name
        ]);

        res.json({
            success: true
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// TOGGLE CHAPTER
app.put('/api/curriculum/chapter/:id/toggle',
authorizeGateway,
async (req, res) => {

    const { is_active } = req.body;

    try {

        await pool.query(`
            UPDATE chapters
            SET is_active = $1
            WHERE id = $2
        `, [
            is_active,
            req.params.id
        ]);

        res.json({
            success: true
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// DELETE CURRICULUM NODE
app.delete('/api/curriculum/:type/:id',
authorizeGateway,
async (req, res) => {

    const map = {
        subject: 'subjects',
        chapter: 'chapters',
        theme: 'themes'
    };

    try {

        await pool.query(`
            DELETE FROM ${map[req.params.type]}
            WHERE id = $1
        `, [req.params.id]);

        res.json({
            success: true
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// ================= STUDENTS =================

app.get('/api/students',
authorizeGateway,
async (req, res) => {

    const { grade } = req.query;

    try {

        const students =
            await pool.query(`
                SELECT *
                FROM students
                WHERE grade_level = $1
                ORDER BY roll_number
            `, [grade]);

        const marks =
            await pool.query(`
                SELECT
                    m.student_id,
                    m.theme_id,
                    m.score

                FROM marks m

                JOIN students s
                ON s.id = m.student_id

                WHERE s.grade_level = $1
            `, [grade]);

        res.json({
            students: students.rows,
            marks: marks.rows
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// BULK STUDENTS
app.post('/api/students/bulk',
authorizeGateway,
async (req, res) => {

    const {
        grade,
        names
    } = req.body;

    try {

        const maxRoll =
            await pool.query(`
                SELECT
                COALESCE(MAX(roll_number),0)
                as max_roll
                FROM students
                WHERE grade_level = $1
            `, [grade]);

        let nextRoll =
            parseInt(
                maxRoll.rows[0].max_roll
            );

        for(let name of names) {

            nextRoll++;

            await pool.query(`
                INSERT INTO students
                (
                    grade_level,
                    student_name,
                    roll_number
                )
                VALUES
                (
                    $1,
                    $2,
                    $3
                )
            `, [
                grade,
                name,
                nextRoll
            ]);
        }

        res.json({
            success: true
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// DELETE STUDENT
app.delete('/api/students/:id',
authorizeGateway,
async (req, res) => {

    try {

        await pool.query(`
            DELETE FROM students
            WHERE id = $1
        `, [req.params.id]);

        res.json({
            success: true
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// ================= MARKS =================

app.post('/api/marks/save',
authorizeGateway,
async (req, res) => {

    const {
        student_id,
        theme_id,
        score
    } = req.body;

    try {

        if(score === null || score === '') {

            await pool.query(`
                DELETE FROM marks
                WHERE student_id = $1
                AND theme_id = $2
            `, [
                student_id,
                theme_id
            ]);

        } else {

            await pool.query(`
                INSERT INTO marks
                (
                    student_id,
                    theme_id,
                    score
                )
                VALUES
                (
                    $1,
                    $2,
                    $3
                )

                ON CONFLICT
                (
                    student_id,
                    theme_id
                )

                DO UPDATE
                SET score = EXCLUDED.score
            `, [
                student_id,
                theme_id,
                score
            ]);
        }

        res.json({
            success: true
        });

    } catch(err) {

        res.status(500).json({
            error: err.message
        });
    }
});

// ================= START SERVER =================

const PORT =
    process.env.PORT || 3000;

initializeDatabase()
.then(() => {

    app.listen(PORT, () => {

        console.log(
            `Server running on port ${PORT}`
        );
    });

})
.catch(err => {

    console.log(err);
});
```
