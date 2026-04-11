<?php
/**
 * Bootstrap endpoint — creates a new account + actor + first API key.
 * No auth required. This is the entry point for new users.
 *
 * POST /bootstrap
 * Body: { "account_name": "...", "actor_name": "...", "actor_type": "agent|human" }
 *
 * Rate limited by IP: 3 accounts per IP per hour.
 * Grants 100 free credits to every new account.
 */

$input = json_decode(file_get_contents('php://input'), true);
$account_name = trim($input['account_name'] ?? '');
$actor_name = trim($input['actor_name'] ?? '');
$actor_type = $input['actor_type'] ?? 'agent';

if (empty($account_name) || empty($actor_name)) {
    http_response_code(400);
    echo json_encode(['error' => 'account_name and actor_name are required']);
    exit;
}

// Restrict actor_type — 'system' is reserved for internal use
if (!in_array($actor_type, ['agent', 'human'])) {
    http_response_code(400);
    echo json_encode(['error' => 'actor_type must be agent or human']);
    exit;
}

// IP-based rate limiting: max 3 bootstraps per IP per hour
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$rate_stmt = $pdo->prepare(
    "SELECT COUNT(*) as cnt FROM accounts
     WHERE created_by_ip = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)"
);
$rate_stmt->execute([$client_ip]);
$recent_count = (int)$rate_stmt->fetch()['cnt'];

if ($recent_count >= 3) {
    http_response_code(429);
    header('Retry-After: 3600');
    echo json_encode(['error' => 'Too many accounts created. Try again later.']);
    exit;
}

// Generate the raw API key
$raw_key = bin2hex(random_bytes(32));
$key_hash = hash('sha256', $raw_key);
$key_prefix = substr($raw_key, 0, 8);

// Derive encryption keypair
$keys = \Crypto\Inbox::deriveKeypair($raw_key);

$pdo->beginTransaction();
try {
    // Create account with 100 free credits
    $stmt = $pdo->prepare("INSERT INTO accounts (name, credit_balance, created_by_ip) VALUES (?, 100, ?)");
    $stmt->execute([$account_name, $client_ip]);
    $account_id = (int)$pdo->lastInsertId();

    // Record the bootstrap grant in credit_ledger
    $stmt = $pdo->prepare(
        "INSERT INTO credit_ledger (account_id, delta, balance_after, reason) VALUES (?, 100, 100, 'bootstrap_grant')"
    );
    $stmt->execute([$account_id]);

    // Create actor with public key
    $stmt = $pdo->prepare(
        "INSERT INTO actors (account_id, name, actor_type, public_key) VALUES (?, ?, ?, ?)"
    );
    $stmt->execute([$account_id, $actor_name, $actor_type, $keys['public_key']]);
    $actor_id = (int)$pdo->lastInsertId();

    // Create API key
    $stmt = $pdo->prepare(
        "INSERT INTO api_keys (account_id, actor_id, api_key_hash, key_prefix, label)
         VALUES (?, ?, ?, ?, ?)"
    );
    $stmt->execute([$account_id, $actor_id, $key_hash, $key_prefix, 'bootstrap key']);

    // Initialize API credits (monthly tracking)
    $stmt = $pdo->prepare(
        "INSERT INTO api_credits (account_id, monthly_limit, period_start) VALUES (?, 10000, CURDATE())"
    );
    $stmt->execute([$account_id]);

    $pdo->commit();

    http_response_code(201);
    echo json_encode([
        'account_id' => $account_id,
        'actor_id' => $actor_id,
        'actor_name' => $actor_name,
        'actor_type' => $actor_type,
        'api_key' => $raw_key,
        'key_prefix' => $key_prefix,
        'public_key_hex' => bin2hex($keys['public_key']),
        'credits' => 100,
        'warning' => 'Store this API key securely — it cannot be retrieved again. This key is also your encryption secret.',
        'mcp_config' => [
            'roots' => [
                'type' => 'stdio',
                'command' => 'node',
                'args' => ['/path/to/roots-mcp/server.js'],
                'env' => ['ROOTS_API_KEY' => $raw_key],
            ],
        ],
    ]);
} catch (\Exception $e) {
    $pdo->rollBack();
    http_response_code(500);
    // Do NOT leak exception details to unauthenticated callers
    echo json_encode(['error' => 'Account creation failed. Please try again.']);
}
