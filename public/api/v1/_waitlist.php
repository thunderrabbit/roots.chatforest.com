<?php
/**
 * Waitlist endpoint — no auth required.
 * POST /waitlist  { "email": "..." }  — sign up + send verification email
 * GET  /waitlist/verify?token=XXX     — verify email
 */

$method = $_SERVER['REQUEST_METHOD'];

// === GET /waitlist/verify?token=XXX ===
if ($method === 'GET') {
    $token = trim($_GET['token'] ?? '');
    if (empty($token) || !preg_match('/^[a-f0-9]{64}$/', $token)) {
        http_response_code(400);
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><html><head><title>Invalid token</title></head><body style="font-family:sans-serif;padding:40px;text-align:center"><h2>Invalid or missing token.</h2></body></html>';
        exit;
    }

    $stmt = $pdo->prepare("SELECT waitlist_id, verified FROM waitlist WHERE verify_token = ?");
    $stmt->execute([$token]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        http_response_code(404);
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><html><head><title>Token not found</title></head><body style="font-family:sans-serif;padding:40px;text-align:center"><h2>Verification token not found.</h2><p>It may have already been used or is invalid.</p></body></html>';
        exit;
    }

    if ($row['verified']) {
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><html><head><title>Already verified</title></head><body style="font-family:sans-serif;padding:40px;text-align:center"><h2>Email already verified!</h2><p>You\'re all set. We\'ll be in touch.</p></body></html>';
        exit;
    }

    $update = $pdo->prepare("UPDATE waitlist SET verified = 1, verified_at = NOW() WHERE waitlist_id = ?");
    $update->execute([$row['waitlist_id']]);

    header('Content-Type: text/html; charset=utf-8');
    echo '<!DOCTYPE html><html><head><title>Email verified</title></head><body style="font-family:sans-serif;padding:40px;text-align:center"><h2>Email verified — thanks!</h2><p>You\'re on the list. We\'ll be in touch when Roots is ready for you.</p></body></html>';
    exit;
}

// === POST /waitlist — sign up ===
$input = json_decode(file_get_contents('php://input'), true);
$email = trim($input['email'] ?? '');

if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['error' => 'A valid email address is required']);
    exit;
}

$ip = $_SERVER['REMOTE_ADDR'] ?? null;

// Simple IP rate limit: max 3 signups per IP per hour
if ($ip) {
    $rate_stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM waitlist WHERE ip_address = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)"
    );
    $rate_stmt->execute([$ip]);
    if ((int)$rate_stmt->fetchColumn() >= 3) {
        http_response_code(429);
        echo json_encode(['error' => 'Too many signups from this IP. Try again later.']);
        exit;
    }
}

// Generate verification token
$token = bin2hex(random_bytes(32));

try {
    $stmt = $pdo->prepare("INSERT INTO waitlist (email, ip_address, verify_token) VALUES (?, ?, ?)");
    $stmt->execute([$email, $ip, $token]);

    // Send verification email
    $email_sent = send_verification_email($email, $token);

    http_response_code(201);
    $msg = "You're on the list. Check your email to verify your address.";
    echo json_encode(['status' => 'ok', 'message' => $msg]);
} catch (\PDOException $e) {
    if ($e->getCode() === '23000') {
        // Duplicate email — don't resend, don't reveal existence
        echo json_encode(['status' => 'ok', 'message' => "You're on the list. Check your email to verify your address."]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Could not save signup']);
    }
}

/**
 * Send verification email via SMTP SSL (port 465).
 */
function send_verification_email(string $to, string $token): bool {
    // Derive home dir from __DIR__ since $_SERVER['HOME'] is unreliable in PHP-FPM
    preg_match('#^(/home/[^/]+)#', __DIR__, $hm);
    $home = $hm[1] ?? '/home/roots_dot_cf';
    $conf_path = $home . '/roots_smtp.conf';
    if (!file_exists($conf_path)) {
        error_log("roots_smtp.conf not found at $conf_path");
        return false;
    }
    $conf = parse_ini_file($conf_path);
    if (!$conf) {
        error_log("Failed to parse roots_smtp.conf");
        return false;
    }

    $host = $conf['SMTP_HOST'];
    $port = (int)$conf['SMTP_PORT'];
    $user = $conf['SMTP_USER'];
    $pass = $conf['SMTP_PASS'];

    $verify_url = "https://roots.chatforest.com/api/v1/waitlist/verify?token=$token";

    $subject = "Verify your Roots waitlist signup";
    $body = "Thanks for signing up for Roots.\r\n\r\nClick here to verify your email:\r\n$verify_url\r\n\r\n— Roots (roots.chatforest.com)\r\n";

    // Build the email message
    $headers = "From: roots@chatforest.com\r\n";
    $headers .= "To: $to\r\n";
    $headers .= "Subject: $subject\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $headers .= "Date: " . date('r') . "\r\n";

    $message = $headers . "\r\n" . $body;

    // Connect via SSL
    $ctx = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
    $fp = stream_socket_client("ssl://$host:$port", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $ctx);

    if (!$fp) {
        error_log("SMTP connect failed: $errstr ($errno)");
        return false;
    }

    // Helper to read SMTP response
    $read = function() use ($fp) {
        $resp = '';
        while ($line = fgets($fp, 512)) {
            $resp .= $line;
            if (isset($line[3]) && $line[3] === ' ') break;
        }
        return $resp;
    };

    // Helper to send command and check response
    $send = function(string $cmd, int $expect) use ($fp, $read) {
        fwrite($fp, $cmd . "\r\n");
        $resp = $read();
        $code = (int)substr($resp, 0, 3);
        if ($code !== $expect) {
            error_log("SMTP unexpected response to " . trim($cmd) . ": " . trim($resp));
            return false;
        }
        return true;
    };

    $ok = true;

    // Read greeting
    $greeting = $read();
    if ((int)substr($greeting, 0, 3) !== 220) {
        error_log("SMTP bad greeting: " . trim($greeting));
        fclose($fp);
        return false;
    }

    $ok = $ok && $send("EHLO roots.chatforest.com", 250);
    $ok = $ok && $send("AUTH LOGIN", 334);
    $ok = $ok && $send(base64_encode($user), 334);
    $ok = $ok && $send(base64_encode($pass), 235);
    $ok = $ok && $send("MAIL FROM:<$user>", 250);
    $ok = $ok && $send("RCPT TO:<$to>", 250);
    $ok = $ok && $send("DATA", 354);

    if ($ok) {
        fwrite($fp, $message . "\r\n.\r\n");
        $resp = $read();
        if ((int)substr($resp, 0, 3) !== 250) {
            error_log("SMTP DATA end failed: " . trim($resp));
            $ok = false;
        }
    }

    $send("QUIT", 221);
    fclose($fp);

    return $ok;
}
