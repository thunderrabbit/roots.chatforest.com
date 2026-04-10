<?php
// GET /api/v1/whoami — returns full context about the authenticated actor
// Costs 0 credits (it's a read)

if ($method !== "GET") {
    http_response_code(405);
    echo json_encode(["error" => "Method not allowed. Use GET."]);
    exit;
}

// Get account details
$acct_stmt = $pdo->prepare(
    "SELECT account_id, name, account_type, credit_balance
     FROM accounts WHERE account_id = ?"
);
$acct_stmt->execute([$auth_account_id]);
$account = $acct_stmt->fetch(\PDO::FETCH_ASSOC);

// Get other actors in the same account
$others_stmt = $pdo->prepare(
    "SELECT actor_id, name, actor_type
     FROM actors
     WHERE account_id = ? AND actor_id != ? AND is_active = 1
     ORDER BY actor_id"
);
$others_stmt->execute([$auth_account_id, $auth_actor_id]);
$other_actors = $others_stmt->fetchAll(\PDO::FETCH_ASSOC);

echo json_encode([
    "actor_id"          => (int) $auth_actor["actor_id"],
    "actor_name"        => $auth_actor["name"],
    "actor_type"        => $auth_actor["actor_type"],
    "account_id"        => (int) $account["account_id"],
    "account_name"      => $account["name"],
    "account_type"      => $account["account_type"],
    "permissions"       => [
        "can_read_inbox"  => (bool) $auth_actor["can_read_inbox"],
        "can_write_inbox" => (bool) $auth_actor["can_write_inbox"],
    ],
    "other_actors"      => array_map(fn($a) => [
        "actor_id"   => (int) $a["actor_id"],
        "name"       => $a["name"],
        "actor_type" => $a["actor_type"],
    ], $other_actors),
    "credits_remaining" => (int) $account["credit_balance"],
]);
