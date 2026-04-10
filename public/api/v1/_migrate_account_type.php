<?php
// One-time migration: add account_type column
// DELETE THIS FILE after running

$secret = $_GET['key'] ?? '';
if ($secret !== 'migrate_account_type_2026') {
    http_response_code(404);
    echo json_encode(["error" => "Not found"]);
    exit;
}

try {
    $pdo->exec("ALTER TABLE accounts ADD COLUMN account_type ENUM('operator','customer') NOT NULL DEFAULT 'customer'");
    $pdo->exec("UPDATE accounts SET account_type = 'operator' WHERE account_id = 10");

    $stmt = $pdo->query("SELECT account_id, name, account_type FROM accounts");
    $rows = $stmt->fetchAll(\PDO::FETCH_ASSOC);

    echo json_encode(["status" => "done", "accounts" => $rows]);
} catch (\PDOException $e) {
    echo json_encode(["error" => $e->getMessage()]);
}
