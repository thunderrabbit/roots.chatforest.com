<?php
/**
 * Waitlist status endpoint — requires API key auth.
 * GET /waitlist/status — returns counts and recent entries
 */

$sub = $segments[3] ?? "";

if ($method !== "GET" || $sub !== "status") {
    http_response_code(405);
    echo json_encode(["error" => "Method not allowed. Use GET /api/v1/waitlist/status"]);
    exit;
}

// Total count
$total = (int) $pdo->query("SELECT COUNT(*) FROM waitlist")->fetchColumn();

// Verified count
$verified = (int) $pdo->query("SELECT COUNT(*) FROM waitlist WHERE verified = 1")->fetchColumn();

// Recent 10 entries
$recent_stmt = $pdo->query(
    "SELECT email, verified, created_at FROM waitlist ORDER BY created_at DESC LIMIT 10"
);
$recent = [];
while ($row = $recent_stmt->fetch(PDO::FETCH_ASSOC)) {
    $recent[] = [
        "email"      => $row["email"],
        "verified"   => (bool) $row["verified"],
        "created_at" => $row["created_at"],
    ];
}

echo json_encode([
    "total"      => $total,
    "verified"   => $verified,
    "unverified" => $total - $verified,
    "recent"     => $recent,
]);
