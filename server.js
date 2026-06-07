const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// A simple test route to prove the server is alive
app.get('/api/test', (req, res) => {
    res.json({ message: "Server is alive and connected!" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SUCCESS: Server is running on port ${PORT}`));
