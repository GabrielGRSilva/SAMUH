const express = require('express');
const mysql = require('mysql');
const child_process = require('child_process');
const app = express();

// Command Injection (A05)
app.get('/run', (req, res) => {
    child_process.exec('ls ' + req.query.dir, (err, stdout) => {
        res.send(stdout);
    });
});

// SQL Injection (A05)
app.get('/user', (req, res) => {
    const query = "SELECT * FROM users WHERE id = " + req.query.id;
    db.query(query, (err, results) => {
        res.json(results);
    });
});

// eval (A05)
app.post('/calc', (req, res) => {
    const result = eval(req.body.expression);
    res.json({ result });
});

// Hardcoded secret (A04)
const JWT_SECRET = "my-super-secret-key-12345";
const API_KEY = "sk_live_abcdef123456";

// Weak crypto (A04)
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');

// Insecure session (A07)
app.use(require('express-session')({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true
}));

// CORS wildcard (A01)
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    next();
});

// Missing helmet (A02)
// No helmet() middleware used

// Console logging secrets (A09)
console.log("User logged in with password:", password);

// Empty catch (A10)
try {
    await riskyOperation();
} catch (e) {}

// Prototype pollution (A08)
Object.assign(target, req.body);

// node-serialize (A08)
const serialize = require('node-serialize');
const obj = serialize.unserialize(req.cookies.data);

// Wildcard dependency in package (A03)
// See package.json

// process.on uncaughtException (A10)
process.on('uncaughtException', (err) => {
    console.log(err);
});

module.exports = app;
