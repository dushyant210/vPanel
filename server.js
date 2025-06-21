const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs');
const csv = require('csv-parser');
const { parse } = require('json2csv');
const moment = require('moment-timezone');
const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

// In-memory stores
const sessions = {};
const licenseCache = new Map();

const API_URL = 'http://127.0.0.1:8555/';
const AUTH_TOKEN = 'DDJgwS2wUIoKnIn9qkc0yqMarrhf59XaaZe79I0A5NC49QBLqlN7aD5PnvqvtCAQ';
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36';
const LICENSES_CSV = 'licenses.csv';
const USERS_CSV = 'users.csv';

// Initialize licenses.csv
if (!fs.existsSync(LICENSES_CSV)) {
    const headers = ['key', 'date', 'username', 'type'];
    const csvData = parse([], { fields: headers });
    fs.writeFileSync(LICENSES_CSV, csvData + '\n', 'utf8');
    console.log('Created licenses.csv with headers');
}

// Initialize users.csv
if (!fs.existsSync(USERS_CSV)) {
    const headers = ['username', 'password', 'balance', 'level', 'total_sales', 'credit_limit'];
    const defaultAdmin = {
        username: 'admin',
        password: 'admin123',
        balance: 1000,
        level: 'admin',
        total_sales: 0,
        credit_limit: 0 // Admin has no credit limit
    };
    const csvData = parse([defaultAdmin], { fields: headers });
    fs.writeFileSync(USERS_CSV, csvData + '\n', 'utf8');
    console.log('Created users.csv with default admin');
}

// Helper to extract license key
function extractLicenseKey(data) {
    if (typeof data === 'string' && data.trim()) {
        const parts = data.split(';');
        if (parts.length >= 1 && parts[0].trim()) return parts[0].trim();
        return data.trim();
    }
    if (typeof data === 'object' && data) {
        const keys = ['key', 'license', 'license_key', 'token', 'code', 'id', 'serial', 'value', 'result', 'data'];
        for (const k of keys) {
            if (data[k]) return extractLicenseKey(data[k]);
        }
        for (const k in data) {
            if (typeof data[k] === 'object' && data[k]) {
                const nestedKey = extractLicenseKey(data[k]);
                if (nestedKey) return nestedKey;
            }
            if (typeof data[k] === 'string' && data[k].trim()) {
                return data[k].trim();
            }
        }
    }
    return null;
}

// Helper to parse license details
function parseLicenseDetails(data) {
    if (typeof data !== 'string' || !data.trim()) return null;
    const parts = data.split(';');
    if (parts.length < 11) return null;

    const convertEpochToIST = (epoch) => {
        if (!epoch || isNaN(epoch)) return 'N/A';
        const timestamp = epoch.length === 13 ? parseInt(epoch) : parseInt(epoch) * 1000;
        return moment(timestamp).tz('Asia/Kolkata').format('MMMM D, YYYY h:mm:ss A');
    };

    return {
        key: parts[0].trim(),
        expiry_time: convertEpochToIST(parts[2]),
        generated_time: convertEpochToIST(parts[3]),
        last_login: convertEpochToIST(parts[4]),
        hwid: parts[5].trim() || 'N/A',
        brand: parts[6].trim() || 'N/A',
        model: parts[7].trim() || 'N/A',
        android: parts[8].trim() || 'N/A',
        ip: parts[9].trim() || 'N/A'
    };
}

// Helper to read users.csv
async function readUsers() {
    return new Promise((resolve, reject) => {
        const users = [];
        fs.createReadStream(USERS_CSV)
            .pipe(csv(['username', 'password', 'balance', 'level', 'total_sales', 'credit_limit']))
            .on('data', (row) => {
                if (row.username && row.password && !isNaN(parseInt(row.balance, 10)) && row.level) {
                    users.push({
                        username: row.username.trim(),
                        password: row.password.trim(),
                        balance: parseInt(row.balance, 10),
                        level: row.level.trim(),
                        total_sales: parseInt(row.total_sales, 10) || 0,
                        credit_limit: parseInt(row.credit_limit, 10) || 0
                    });
                }
            })
            .on('end', () => resolve(users))
            .on('error', reject);
    });
}

// Helper to update users.csv
async function updateUsers(users) {
    const csvData = parse(users, { fields: ['username', 'password', 'balance', 'level', 'total_sales', 'credit_limit'] });
    fs.writeFileSync(USERS_CSV, csvData + '\n', 'utf8');
    console.log('Updated users.csv');
}

// Helper to update user balance, sales, and credit limit
async function updateUserBalanceAndSales(username, newBalance, newSales, creditLimit = null) {
    const users = await readUsers();
    const updatedUsers = users.map(user =>
        user.username === username ? {
            ...user,
            balance: newBalance,
            total_sales: newSales,
            credit_limit: creditLimit !== null ? creditLimit : user.credit_limit
        } : user
    );
    await updateUsers(updatedUsers);
    console.log(`Updated balance for ${username}: ${newBalance}, sales: ${newSales}, credit_limit: ${creditLimit !== null ? creditLimit : updatedUsers.find(u => u.username === username).credit_limit}`);
}

// Background poller for license details
async function pollLicenseDetails(key) {
    try {
        const response = await axios.post(API_URL, {}, {
            headers: {
                'Auth-Token': AUTH_TOKEN,
                'User-Agent': USER_AGENT,
                'X-BrowserData': `GetKey;1;15;${key}`,
                'Content-Type': 'application/json'
            }
        });

        console.log(`Poll response for ${key}:`, {
            status: response.status,
            headers: response.headers,
            data: response.data
        });

        const details = parseLicenseDetails(response.data);
        if (details) {
            licenseCache.set(key, details);
            console.log(`Updated cache for ${key}:`, details);
        }
    } catch (error) {
        console.error(`Error polling license ${key}:`, error.message, error.response?.data);
    }
}

// Start polling for all licenses
function startLicensePolling() {
    setInterval(() => {
        fs.createReadStream(LICENSES_CSV)
            .pipe(csv(['key', 'date', 'username', 'type']))
            .on('data', (row) => {
                if (row.key && row.key.trim()) {
                    pollLicenseDetails(row.key.trim());
                }
            })
            .on('end', () => console.log('Completed polling cycle'))
            .on('error', (error) => console.error('Error reading licenses.csv for polling:', error));
    }, 5000);
}

// Middleware to check authentication
function requireAuth(req, res, next) {
    const sessionId = req.headers['x-session-id'];
    if (!sessionId || !sessions[sessionId]) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    req.user = sessions[sessionId];
    next();
}

// Middleware to check admin
function requireAdmin(req, res, next) {
    if (req.user.level !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// Login Endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const users = await readUsers();
        const user = users.find(u => u.username === username && u.password === password);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const sessionId = Math.random().toString(36).substring(2);
        sessions[sessionId] = { username: user.username, level: user.level };
        res.json({ success: true, sessionId, user: { username: user.username, balance: user.balance, level: user.level, total_sales: user.total_sales, credit_limit: user.credit_limit } });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// Generate License Endpoint
app.post('/generate-license', requireAuth, async (req, res) => {
    const { product, duration } = req.body;
    const username = req.user.username;
    if (!['Vision', 'Lethal'].includes(product) || !['Day', 'Week'].includes(duration)) {
        console.error('Invalid license parameters:', { product, duration });
        return res.status(400).json({ error: 'Invalid product or duration. Must be Vision/Lethal and Day/Week.' });
    }

    const cost = duration === 'Day' ? 100 : 450;
    const licenseType = `${product}-${duration}`;
    const browserData = `GenerateKeyBrowser;${product};${duration};1`;

    try {
        const users = await readUsers();
        const user = users.find(u => u.username === username);
        if (user.level === 'level2' && user.balance < cost) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        if (user.level === 'level1' && user.balance + cost > user.credit_limit) {
            return res.status(400).json({ error: `Credit limit (${user.credit_limit}) exceeded. Current balance: ${user.balance}, Cost: ${cost}` });
        }

        const response = await axios.post(API_URL, {}, {
            headers: {
                'Auth-Token': AUTH_TOKEN,
                'User-Agent': USER_AGENT,
                'X-BrowserData': browserData,
                'Content-Type': 'application/json'
            }
        });

        console.log('Main server response for generate:', {
            status: response.status,
            headers: response.headers,
            data: response.data
        });

        const licenseKey = extractLicenseKey(response.data);
        if (!licenseKey || typeof licenseKey !== 'string' || licenseKey.trim() === '') {
            throw new Error('No valid license key found in response');
        }

        // Fetch license details
        const detailsResponse = await axios.post(API_URL, {}, {
            headers: {
                'Auth-Token': AUTH_TOKEN,
                'User-Agent': USER_AGENT,
                'X-BrowserData': `GetKey;1;15;${licenseKey}`,
                'Content-Type': 'application/json'
            }
        });

        const licenseDetails = parseLicenseDetails(detailsResponse.data);
        if (!licenseDetails) {
            throw new Error('Invalid license details response');
        }

        // Update balance and sales
        const newBalance = user.level === 'level1' ? user.balance + cost : user.balance - cost;
        const newSales = user.total_sales + cost;
        await updateUserBalanceAndSales(username, newBalance, newSales);

        const license = {
            key: licenseKey,
            date: new Date().toISOString(),
            username,
            type: licenseType
        };

        // Append to licenses.csv
        try {
            const csvData = parse([license], { fields: ['key', 'date', 'username', 'type'], header: false });
            fs.appendFileSync(LICENSES_CSV, csvData + '\n', 'utf8');
            console.log('License appended to CSV:', license);
        } catch (csvError) {
            console.error('Error writing to licenses.csv:', csvError);
            return res.status(500).json({ error: `Failed to save license to CSV: ${csvError.message}` });
        }

        // Update cache
        licenseCache.set(licenseKey, licenseDetails);
        res.json({ success: true, key: licenseKey, balance: newBalance, license: licenseDetails });
    } catch (error) {
        console.error('Error generating license:', error.message, error.response?.data);
        res.status(500).json({ error: `Failed to generate license: ${error.message}` });
    }
});

// Reset License Endpoint
app.post('/reset-license', requireAuth, async (req, res) => {
    const { key } = req.body;
    if (!key) {
        console.error('Missing key for reset:', { key });
        return res.status(400).json({ error: 'License key is required' });
    }

    try {
        const browserData = `ResetHWIDBrowser;${key}`;
        const response = await axios.post(API_URL, {}, {
            headers: {
                'Auth-Token': AUTH_TOKEN,
                'User-Agent': USER_AGENT,
                'X-BrowserData': browserData,
                'Content-Type': 'application/json'
            }
        });

        console.log('Main server response for reset:', {
            status: response.status,
            headers: response.headers,
            data: response.data
        });

        const isSuccess = response.status === 200 || (
            typeof response.data === 'object' && (
                response.data.status === 'success' ||
                response.data.message?.toLowerCase().includes('success') ||
                response.data.success === true
            )
        ) || (typeof response.data === 'string' && response.data.toLowerCase().includes('success'));

        if (isSuccess) {
            res.json({ success: true, message: `License ${key} reset successfully` });
        } else {
            console.error('Invalid reset response:', response.data);
            res.status(500).json({ error: `Failed to reset license ${key}: Invalid response from main server` });
        }
    } catch (error) {
        console.error('Error resetting license:', error.message, error.response?.data);
        res.status(500).json({ error: `Failed to reset license ${key}: ${error.message}` });
    }
});

// Get Balance Endpoint
app.get('/balance', requireAuth, async (req, res) => {
    const username = req.user.username;
    try {
        const users = await readUsers();
        const user = users.find(u => u.username === username);
        console.log(`Returning balance for ${username}: ${user.balance}, credit_limit: ${user.credit_limit}`);
        res.json({ balance: user.balance, total_sales: user.total_sales, credit_limit: user.credit_limit });
    } catch (error) {
        console.error('Error reading balance:', error);
        res.status(500).json({ error: 'Failed to read balance' });
    }
});

// Get License History Endpoint
app.get('/licenses', requireAuth, (req, res) => {
    const username = req.user.username;
    const licenses = [];
    fs.createReadStream(LICENSES_CSV)
        .pipe(csv(['key', 'date', 'username', 'type']))
        .on('data', (row) => {
            if (row.key && row.key.trim() && row.date && row.username === username) {
                const cached = licenseCache.get(row.key.trim()) || {};
                licenses.push({
                    key: row.key.trim(),
                    expiry_time: cached.expiry_time || 'N/A',
                    generated_time: cached.generated_time || 'N/A',
                    last_login: cached.last_login || 'N/A',
                    hwid: cached.hwid || 'N/A',
                    brand: cached.brand || 'N/A',
                    model: cached.model || 'N/A',
                    android: cached.android || 'N/A',
                    ip: cached.ip || 'N/A',
                    date: row.date.trim() || new Date().toISOString(),
                    type: row.type || 'N/A'
                });
            }
        })
        .on('end', () => {
            console.log(`Returning licenses for ${username}:`, licenses);
            res.json({ licenses });
        })
        .on('error', (error) => {
            console.error('Error reading licenses.csv:', error);
            res.status(500).json({ error: `Failed to read licenses from CSV: ${error.message}` });
        });
});

// Admin: Get All Users (exclude admin)
app.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await readUsers();
        const filteredUsers = users.filter(user => user.level !== 'admin');
        res.json({ success: true, users: filteredUsers });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Admin: Create User
app.post('/admin/users', requireAuth, requireAdmin, async (req, res) => {
    const { username, password, level, credit_limit } = req.body;
    if (!username || !password || !['level1', 'level2'].includes(level) || (level === 'level1' && (isNaN(credit_limit) || credit_limit < 0))) {
        return res.status(400).json({ error: 'Invalid user data. Username, password, level (level1 or level2), and credit_limit (non-negative for level1) required.' });
    }

    try {
        const users = await readUsers();
        if (users.find(u => u.username === username)) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const newUser = {
            username,
            password,
            balance: 0,
            level,
            total_sales: 0,
            credit_limit: level === 'level1' ? parseInt(credit_limit, 10) : 0
        };
        users.push(newUser);
        await updateUsers(users);
        res.json({ success: true, message: 'User created successfully' });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

// Admin: Update User
app.post('/admin/users/:username', requireAuth, requireAdmin, async (req, res) => {
    const { username } = req.params;
    const { newUsername, password, level, credit_limit } = req.body;
    if (!newUsername || !password || !['level1', 'level2'].includes(level) || (level === 'level1' && (isNaN(credit_limit) || credit_limit < 0))) {
        return res.status(400).json({ error: 'Invalid user data. New username, password, level (level1 or level2), and credit_limit (non-negative for level1) required.' });
    }

    try {
        const users = await readUsers();
        const userExists = users.find(u => u.username === username);
        if (!userExists) {
            return res.status(404).json({ error: 'User not found' });
        }

        const updatedUsers = users.map(user =>
            user.username === username ? {
                username: newUsername,
                password,
                balance: user.balance,
                level,
                total_sales: user.total_sales,
                credit_limit: level === 'level1' ? parseInt(credit_limit, 10) : 0
            } : user
        );
        await updateUsers(updatedUsers);

        // Update sessions if username changed
        if (username !== newUsername) {
            for (const sessionId in sessions) {
                if (sessions[sessionId].username === username) {
                    sessions[sessionId].username = newUsername;
                }
            }
        }

        res.json({ success: true, message: 'User updated successfully' });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// Admin: Adjust Balance
app.post('/admin/users/:username/balance', requireAuth, requireAdmin, async (req, res) => {
    const { username } = req.params;
    const { amount, operation } = req.body;
    if (!['add', 'subtract'].includes(operation) || isNaN(amount) || amount < 0) {
        return res.status(400).json({ error: 'Invalid operation or amount' });
    }

    try {
        const users = await readUsers();
        const user = users.find(u => u.username === username);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const newBalance = operation === 'add' ? user.balance + amount : user.balance - amount;
        if (newBalance < 0) {
            return res.status(400).json({ error: 'Balance cannot be negative' });
        }

        await updateUserBalanceAndSales(username, newBalance, user.total_sales);
        res.json({ success: true, balance: newBalance });
    } catch (error) {
        console.error('Error adjusting balance:', error);
        res.status(500).json({ error: 'Failed to adjust balance' });
    }
});

// Admin: Make Payment
app.post('/admin/users/:username/pay', requireAuth, requireAdmin, async (req, res) => {
    const { username } = req.params;
    const { amount } = req.body;
    if (isNaN(amount) || amount <= 0) {
        return res.status(400).json({ error: 'Invalid payment amount. Must be a positive number.' });
    }

    try {
        const users = await readUsers();
        const user = users.find(u => u.username === username);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (user.level !== 'level1') {
            return res.status(400).json({ error: 'Payments are only applicable to Level 1 (Credit) users' });
        }

        const newBalance = user.balance - amount;
        await updateUserBalanceAndSales(username, newBalance, user.total_sales);
        res.json({ success: true, balance: newBalance, message: `Payment of ${amount} applied successfully` });
    } catch (error) {
        console.error('Error processing payment:', error);
        res.status(500).json({ error: 'Failed to process payment' });
    }
});

// Admin: Get User Licenses
app.get('/admin/users/:username/licenses', requireAuth, requireAdmin, (req, res) => {
    const { username } = req.params;
    const licenses = [];
    fs.createReadStream(LICENSES_CSV)
        .pipe(csv(['key', 'date', 'username', 'type']))
        .on('data', (row) => {
            if (row.key && row.key.trim() && row.date && row.username === username) {
                const cached = licenseCache.get(row.key.trim()) || {};
                licenses.push({
                    key: row.key.trim(),
                    expiry_time: cached.expiry_time || 'N/A',
                    generated_time: cached.generated_time || 'N/A',
                    last_login: cached.last_login || 'N/A',
                    hwid: cached.hwid || 'N/A',
                    brand: cached.brand || 'N/A',
                    model: cached.model || 'N/A',
                    android: cached.android || 'N/A',
                    ip: cached.ip || 'N/A',
                    date: row.date.trim() || new Date().toISOString(),
                    type: row.type || 'N/A'
                });
            }
        })
        .on('end', () => {
            console.log(`Returning licenses for ${username}:`, licenses);
            res.json({ licenses });
        })
        .on('error', (error) => {
            console.error('Error reading licenses.csv:', error);
            res.status(500).json({ error: `Failed to read licenses from CSV: ${error.message}` });
        });
});

// Start polling
startLicensePolling();

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});