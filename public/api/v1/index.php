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

$pdo = \Database\Base::getPDO($config);

// Health check — no auth required
if ($resource === "health") {
    echo json_encode(["status" => "ok", "service" => "roots.chatforest.com", "time" => gmdate("c")]);
    exit;
}

// Bootstrap — no auth required (creates first account + actor + key)
if ($resource === "bootstrap" && $_SERVER["REQUEST_METHOD"] === "POST") {
    include __DIR__ . "/_bootstrap.php";
    exit;
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

// Route to resource handlers
$handler_map = [
    "inbox"  => "_inbox.php",
    "actors" => "_actors.php",
    "keys"     => "_keys.php",
    "notebook"   => "_notebook.php",
    "sessions"   => "_sessions.php",
    "todos"      => "_todos.php",
    "activities" => "_activities.php",
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
