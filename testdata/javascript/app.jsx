import React from 'react';

// DOM XSS (A05)
document.getElementById('output').innerHTML = userInput;
document.write(location.hash);

// React dangerouslySetInnerHTML (A05)
function UserProfile({ bio }) {
    return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}

// localStorage token storage (A07)
localStorage.setItem('authToken', response.token);
sessionStorage.setItem('refreshToken', token);

// Hardcoded API key (A04)
const API_KEY = "AIzaSyB1234567890abcdef";
const SECRET = "ghp_1234567890abcdef1234567890abcdef12";

// Prototype pollution (A08)
obj.__proto__.admin = true;
obj.constructor.prototype.isAdmin = true;

// postMessage without origin check (A08)
window.addEventListener('message', (event) => {
    processData(event.data);
});

// Empty catch (A10)
fetch('/api/data').catch(() => {});

// Console log in production (A09)
console.log('User data:', userData);

// eval usage (A05)
setTimeout("doSomething('" + userInput + "')", 100);

// Open redirect (A01)
window.location.href = params.get('redirect');

// Missing CSP (A02)
// eslint-disable-next-line no-eval
const result = eval(input);

// Credentials in URL (A07)
fetch(`https://api.example.com?api_key=${apiKey}&secret=${secret}`);

// Unchecked JSON.parse (A10)
const data = JSON.parse(untrustedInput);

// Vue v-html (A05)
// <div v-html="userContent"></div>

// Script without SRI (A03)
// <script src="https://cdn.example.com/lib.js"></script>
