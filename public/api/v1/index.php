<?php
preg_match("#^(/home/[^/]+/[^/]+)#", __DIR__, $matches);
include_once $matches[1] . "/prepend.php";

header("Content-Type: application/json");

// CORS
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: X-API-Key, Content-Type");
header("Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS");
if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    http_response_code(204);
    exit;
}

$path = trim(parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH), "/");
$segments = explode("/", $path);
$resource = $segments[2] ?? "";
$method = $_SERVER["REQUEST_METHOD"];

$pdo = \Database\Base::getPDO($config);

// Health check — no auth required
if ($resource === "health") {
    echo json_encode(["status" => "ok", "service" => "roots.chatforest.com", "time" => gmdate("c")]);
    exit;
}

// Bootstrap — no auth required (creates first account + actor + key)
if ($resource === "bootstrap" && $method === "POST") {
    include __DIR__ . "/_bootstrap.php";
    exit;
}

// Waitlist — sign up and verify are unauthenticated; status requires auth (falls through)
if ($resource === "waitlist") {
    $sub = $segments[3] ?? "";
    if ($method === "POST" && $sub === "") {
        include __DIR__ . "/_waitlist.php";
        exit;
    }
    if ($method === "GET" && $sub === "verify") {
        include __DIR__ . "/_waitlist.php";
        exit;
    }
}

// === Auth required for everything below ===
$raw_key = $_SERVER["HTTP_X_API_KEY"] ?? "";
if (empty($raw_key)) {
    http_response_code(401);
    echo json_encode(["error" => "Missing X-API-Key header"]);
    exit;
}

$auth = new \Auth\ApiKey($pdo);
$auth_account_id = $auth->validateKey($raw_key);

if ($auth_account_id === null) {
    http_response_code(401);
    echo json_encode(["error" => "Invalid API key"]);
    exit;
}

$auth_key_id = $auth->getLastKeyId();
$auth_actor_id = $auth->getLastActorId();

// Look up actor details
$actor_stmt = $pdo->prepare(
    "SELECT a.actor_id, a.account_id, a.name, a.actor_type,
            a.can_read_inbox, a.can_write_inbox, a.public_key
     FROM actors a
     WHERE a.actor_id = ? AND a.account_id = ? AND a.is_active = 1"
);
$actor_stmt->execute([$auth_actor_id, $auth_account_id]);
$auth_actor = $actor_stmt->fetch(\PDO::FETCH_ASSOC);

if (!$auth_actor) {
    http_response_code(403);
    echo json_encode(["error" => "No active actor linked to this API key"]);
    exit;
}

// === Rate limiting: 120 requests per key per minute ===
$rate_limit = 120;
$window_start = date("Y-m-d H:i:s", time() - 60);
$rate_stmt = $pdo->prepare(
    "SELECT COUNT(*) AS cnt FROM api_usage
     WHERE key_id = ? AND called_at >= ?"
);
$rate_stmt->execute([$auth_key_id, $window_start]);
$request_count = (int) $rate_stmt->fetch(\PDO::FETCH_ASSOC)["cnt"];

if ($request_count >= $rate_limit) {
    http_response_code(429);
    header("Retry-After: 60");
    echo json_encode(["error" => "Rate limit exceeded", "limit" => $rate_limit, "window" => "60s"]);
    exit;
}

// === Credit metering: writes cost 1, reads cost 0 ===
$is_write = in_array($method, ["POST", "PATCH", "DELETE"]);
$credit_cost = $is_write ? 1 : 0;

if ($credit_cost > 0) {
    $bal_stmt = $pdo->prepare("SELECT credit_balance FROM accounts WHERE account_id = ?");
    $bal_stmt->execute([$auth_account_id]);
    $balance = (int) $bal_stmt->fetchColumn();

    if ($balance < $credit_cost) {
        http_response_code(402);
        echo json_encode([
            "error" => "Insufficient credits",
            "balance" => $balance,
            "cost" => $credit_cost,
            "top_up" => "POST /api/v1/credits with a top-up grant (contact admin)",
        ]);
        exit;
    }

    // Debit the credit
    $pdo->exec("UPDATE accounts SET credit_balance = credit_balance - $credit_cost WHERE account_id = $auth_account_id");

    // Get new balance for ledger
    $bal_stmt->execute([$auth_account_id]);
    $new_balance = (int) $bal_stmt->fetchColumn();

    $endpoint_name = $resource . "/" . ($segments[3] ?? "");
    $endpoint_name = rtrim($endpoint_name, "/");

    $ledger_stmt = $pdo->prepare(
        "INSERT INTO credit_ledger (account_id, delta, balance_after, reason, related_endpoint)
         VALUES (?, ?, ?, ?, ?)"
    );
    $ledger_stmt->execute([$auth_account_id, -$credit_cost, $new_balance, "api_write", $method . " " . $endpoint_name]);
}

// === Audit log: record this request ===
$endpoint = $resource . "/" . ($segments[3] ?? "");
$endpoint = rtrim($endpoint, "/");
$log_stmt = $pdo->prepare(
    "INSERT INTO api_usage (key_id, endpoint, method, called_at) VALUES (?, ?, ?, NOW())"
);
$log_stmt->execute([$auth_key_id, $endpoint, $method]);

// === Increment monthly usage counter (api_credits table) ===
$period_start = date("Y-m-01");
$credit_stmt = $pdo->prepare(
    "SELECT credit_id FROM api_credits WHERE account_id = ? AND period_start = ?"
);
$credit_stmt->execute([$auth_account_id, $period_start]);
$credit_row = $credit_stmt->fetch(\PDO::FETCH_ASSOC);

if ($credit_row) {
    $pdo->prepare("UPDATE api_credits SET used_this_month = used_this_month + 1 WHERE credit_id = ?")
        ->execute([$credit_row["credit_id"]]);
} else {
    $pdo->prepare(
        "INSERT INTO api_credits (account_id, monthly_limit, used_this_month, period_start) VALUES (?, 10000, 1, ?)"
    )->execute([$auth_account_id, $period_start]);
}

// Route to resource handlers
$handler_map = [
    "inbox"      => "_inbox.php",
    "actors"     => "_actors.php",
    "keys"       => "_keys.php",
    "notebook"   => "_notebook.php",
    "sessions"   => "_sessions.php",
    "todos"      => "_todos.php",
    "activities" => "_activities.php",
    "usage"      => "_usage.php",
    "credits"    => "_credits.php",
    "waitlist"   => "_waitlist_status.php",
];

if (isset($handler_map[$resource])) {
    include __DIR__ . "/" . $handler_map[$resource];
} else {
    http_response_code(404);
    echo json_encode([
        "error" => "Unknown resource: " . $resource,
        "available" => array_keys($handler_map),
    ]);
}
