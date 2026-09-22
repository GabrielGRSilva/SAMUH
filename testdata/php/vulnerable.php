<?php
// VULNERABLE CODE - Test fixture for SAMUH

// SQL Injection (A05)
$id = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id = " . $id);

// XSS (A05)
echo $_GET['name'];
echo "<h1>" . $_REQUEST['title'] . "</h1>";

// Command Injection (A05)
$file = $_POST['filename'];
system("cat " . $file);
exec("rm " . $_GET['path']);

// Weak Crypto (A04)
$hash = md5($password);
$token = sha1($secret);

// Hardcoded credentials (A04)
$db_password = "SuperSecret123!";
$api_key = "sk-1234567890abcdef";

// Insecure deserialization (A08)
$data = unserialize($_COOKIE['session_data']);

// eval (A08)
eval($_POST['code']);

// Debug mode (A02)
ini_set('display_errors', 1);
error_reporting(E_ALL);

// File Inclusion (A05)
include($_GET['page'] . '.php');

// Weak randomness (A04)
$token = rand();
$csrf_token = mt_rand();

// Session issues (A07)
ini_set('session.cookie_httponly', 0);

// Empty catch (A10)
try {
    dangerousOperation();
} catch (Exception $e) {
}

// Logging secrets (A09)
error_log("User login with password: " . $password);

// Form without CSRF (A06)
echo '<form method="post" action="/transfer">';
echo '<input name="amount">';
echo '</form>';

// SSRF (A01)
$url = $_GET['url'];
$content = file_get_contents($url);
