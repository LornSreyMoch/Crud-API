const express = require('express');
const app = express();
const pool = require('./db'); // PostgreSQL connection
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');

dotenv.config();

const PORT = process.env.PORT || 4001;
const jwtSecretKey = process.env.JWT_SECRET;

app.use(express.json());

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Middleware for token authentication
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, jwtSecretKey, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Middleware for admin role verification
const authenticateAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied, admin only' });
    }
    next();
};

// Signup route to create new users
app.post('/signup', async (req, res) => {
    const { username, password, role } = req.body;

    try {
        const existingUser = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10); // Hash password

        await pool.query(
            'INSERT INTO public.users(username, password, role) VALUES ($1, $2, $3)', 
            [username, hashedPassword, role]
        );

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        // Log detailed error information
        console.error('Signup error:', error.message);
        console.error('Error stack:', error.stack);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        console.log('Username:', username);
        console.log('User from DB:', user);
        console.log('Password entered:', password);

        if (!user) {
            return res.status(403).json({ error: 'Invalid username or password' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        console.log('Password match result:', passwordMatch);

        if (!passwordMatch) {
            return res.status(403).json({ error: 'Invalid username or password' });
        }

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, jwtSecretKey, { expiresIn: '12h' });

        res.status(200).json({ token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Admin routes
app.use('/admin', authenticateToken, authenticateAdmin);

// Convert a link (authenticated users)
app.get('/admin/links', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT u.id AS user_id, u.username, l.original_link, l.converted_link
            FROM users u
            JOIN links l ON u.id = l.user_id`
        );

        const users = {};

        result.rows.forEach(row => {
            if (!users[`user_${row.user_id}`]) {
                users[`user_${row.user_id}`] = {
                    username: row.username,
                    list_of_converted_links: {}
                };
            }
            // Use correct field names
            users[`user_${row.user_id}`].list_of_converted_links[row.original_link] = row.converted_link;
        });

        res.status(200).json({
            code: 200,
            users
        });
    } catch (error) {
        console.error('Admin links error:', error.message);
        res.status(500).json({ response: 500, error: 'Something went wrong' });
    }
});




// Convert a link (authenticated users)
app.post('/convert', authenticateToken, async (req, res) => {
    const { link } = req.body;

    try {
        // Verify if req.user exists
        console.log('User:', req.user);
        const user = req.user;

        // Generate the shortened link
        const shortened_link = `https://short.ly/${Math.random().toString(36).substring(2, 7)}`;

        // Insert the new link into the database
        console.log('Running query...');
        const result = await pool.query(
            'INSERT INTO public.links(original_link, converted_link, user_id) VALUES ($1, $2, $3) RETURNING *',
            [link, shortened_link, user.id]
        );

        // Log the query result for debugging
        console.log('Query result:', result.rows[0]);

        // Correct the response to use the defined variable
        res.status(200).json({ code: 200, converted_link: shortened_link, lifespan: 0 });
    } catch (error) {
        // Log error details for debugging
        console.error('Conversion error:', error);
        res.status(500).json({ response: 500, error: error.message || 'Something went wrong' });
    }
});


// Delete a specific link (admin only)
app.delete('/admin/links/:id', async (req, res) => {
    const { id } = req.params;
    try {
        // Check if the link exists
        const linkCheck = await pool.query('SELECT * FROM links WHERE id = $1', [id]);
        if (linkCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Link not found' });
        }

        // Proceed to delete the link
        await pool.query('DELETE FROM links WHERE id = $1', [id]);

        res.status(200).json({ message: 'Link deleted successfully' });
    } catch (error) {
        console.error('Error details:', error);
        res.status(500).json({ response: 500, error: 'Something went wrong' });
    }
});

/// Update a specific link (admin only)
app.put('/admin/links/:id', async (req, res) => {
    const { id } = req.params;
    const { original_link, converted_link } = req.body;

    // Validate request body
    if (!original_link || !converted_link) {
        return res.status(400).json({ error: 'Original link and converted link are required' });
    }

    try {
        // Check if the link exists
        const linkCheck = await pool.query('SELECT * FROM links WHERE id = $1', [id]);
        if (linkCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Link not found' });
        }

        // Update the link in the database
        await pool.query(
            'UPDATE links SET original_link = $1, converted_link = $2 WHERE id = $3',
            [original_link, converted_link, id]
        );

        res.status(200).json({ message: 'Link updated successfully' });
    } catch (error) {
        // Enhanced error logging
        console.error('Error updating link:', error);
        res.status(500).json({ error: error.message || 'Something went wrong' });
    }
});
