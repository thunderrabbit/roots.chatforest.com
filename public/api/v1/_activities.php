<?php
/**
 * Activities + Stats endpoints — encrypted descriptions
 *
 * Activities:
 *   GET    /activities              — list activities (with filters)
 *   GET    /activities/{id}         — get single activity
 *   POST   /activities              — log an activity
 *   DELETE /activities/{id}         — delete activity
 *
 * Stats (sub-resource):
 *   GET    /activities/stats        — aggregated stats
 */

$method = $_SERVER["REQUEST_METHOD"];
$id_or_sub = $segments[3] ?? null;

$notebook_key = \Crypto\Notebook::deriveKey($raw_key);
$my_actor_id = (int)$auth_actor["actor_id"];

// Helper: decrypt an activity row
function decryptActivity(array $row, string $key): array {
    $desc = \Crypto\Notebook::decrypt(
        $row["description_ciphertext"], $row["description_nonce"], $key
    );
    return [
        "activity_id"   => (int)$row["activity_id"],
        "session_id"    => $row["session_id"] ? (int)$row["session_id"] : null,
        "activity_type" => $row["activity_type"],
        "description"   => $desc !== false ? $desc : "[DECRYPTION FAILED]",
        "logged_at"     => $row["logged_at"],
        "created_at"    => $row["created_at"],
    ];
}

// === Stats sub-resource ===
if ($id_or_sub === "stats" && $method === "GET") {
    $since = $_GET["since"] ?? null;
    $until = $_GET["until"] ?? null;
    $session_id = isset($_GET["session_id"]) ? (int)$_GET["session_id"] : null;

    $where = "actor_id = ?";
    $params = [$my_actor_id];

    if ($since !== null) {
        $where .= " AND logged_at >= ?";
        $params[] = $since;
    }
    if ($until !== null) {
        $where .= " AND logged_at <= ?";
        $params[] = $until;
    }
    if ($session_id !== null) {
        $where .= " AND session_id = ?";
        $params[] = $session_id;
    }

    // Count by type
    $stmt = $pdo->prepare(
        "SELECT activity_type, COUNT(*) as count
         FROM activities WHERE $where
         GROUP BY activity_type ORDER BY count DESC"
    );
    $stmt->execute($params);
    $by_type = $stmt->fetchAll();

    // Count by day (last 30 days)
    $stmt = $pdo->prepare(
        "SELECT DATE(logged_at) as day, COUNT(*) as count
         FROM activities WHERE $where
         GROUP BY DATE(logged_at) ORDER BY day DESC LIMIT 30"
    );
    $stmt->execute($params);
    $by_day = $stmt->fetchAll();

    // Total
    $stmt = $pdo->prepare("SELECT COUNT(*) as total FROM activities WHERE $where");
    $stmt->execute($params);
    $total = (int)$stmt->fetch()["total"];

    // Sessions count
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) as total, SUM(status = 'active') as active
         FROM sessions WHERE actor_id = ?"
    );
    $stmt->execute([$my_actor_id]);
    $session_stats = $stmt->fetch();

    echo json_encode([
        "total_activities" => $total,
        "by_type"          => $by_type,
        "by_day"           => $by_day,
        "sessions"         => [
            "total"  => (int)$session_stats["total"],
            "active" => (int)$session_stats["active"],
        ],
    ]);
    exit;
}

$id_param = $id_or_sub !== null ? (int)$id_or_sub : null;
if ($id_or_sub !== null && $id_param === 0) {
    $id_param = null; // non-numeric sub-resource already handled
}

switch ($method) {
    case "GET":
        if ($id_param) {
            // GET /activities/{id}
            $stmt = $pdo->prepare(
                "SELECT activity_id, session_id, activity_type,
                        description_ciphertext, description_nonce,
                        logged_at, created_at
                 FROM activities WHERE activity_id = ? AND actor_id = ?"
            );
            $stmt->execute([$id_param, $my_actor_id]);
            $row = $stmt->fetch();

            if (!$row) {
                http_response_code(404);
                echo json_encode(["error" => "Activity not found"]);
                break;
            }

            echo json_encode(decryptActivity($row, $notebook_key));
        } else {
            // GET /activities — list
            $type_filter = $_GET["type"] ?? null;
            $session_filter = isset($_GET["session_id"]) ? (int)$_GET["session_id"] : null;
            $since = $_GET["since"] ?? null;
            $until = $_GET["until"] ?? null;
            $limit = min((int)($_GET["limit"] ?? 50), 100);
            $offset = max((int)($_GET["offset"] ?? 0), 0);

            $where = "actor_id = ?";
            $params = [$my_actor_id];

            if ($type_filter !== null) {
                $where .= " AND activity_type = ?";
                $params[] = $type_filter;
            }
            if ($session_filter !== null) {
                $where .= " AND session_id = ?";
                $params[] = $session_filter;
            }
            if ($since !== null) {
                $where .= " AND logged_at >= ?";
                $params[] = $since;
            }
            if ($until !== null) {
                $where .= " AND logged_at <= ?";
                $params[] = $until;
            }

            $params[] = $limit;
            $params[] = $offset;

            $stmt = $pdo->prepare(
                "SELECT activity_id, session_id, activity_type,
                        description_ciphertext, description_nonce,
                        logged_at, created_at
                 FROM activities WHERE $where
                 ORDER BY logged_at DESC LIMIT ? OFFSET ?"
            );
            $stmt->execute($params);
            $rows = $stmt->fetchAll();

            $activities = [];
            foreach ($rows as $row) {
                $activities[] = decryptActivity($row, $notebook_key);
            }

            // Total count
            $count_params = array_slice($params, 0, -2);
            $count_stmt = $pdo->prepare(
                "SELECT COUNT(*) as total FROM activities WHERE $where"
            );
            $count_stmt->execute($count_params);
            $total = (int)$count_stmt->fetch()["total"];

            echo json_encode([
                "activities" => $activities,
                "total"      => $total,
                "limit"      => $limit,
                "offset"     => $offset,
            ]);
        }
        break;

    case "POST":
        $input = json_decode(file_get_contents("php://input"), true);
        $description = $input["description"] ?? "";
        $activity_type = $input["activity_type"] ?? "general";
        $session_id = isset($input["session_id"]) ? (int)$input["session_id"] : null;
        $logged_at = $input["logged_at"] ?? null;

        if (empty($description)) {
            http_response_code(400);
            echo json_encode(["error" => "description is required"]);
            break;
        }

        // Validate activity_type (alphanumeric + underscore, max 50)
        if (!preg_match('/^[a-z0-9_]{1,50}$/', $activity_type)) {
            http_response_code(400);
            echo json_encode(["error" => "activity_type must be lowercase alphanumeric with underscores, max 50 chars"]);
            break;
        }

        // Validate session ownership if provided
        if ($session_id !== null) {
            $stmt = $pdo->prepare("SELECT session_id FROM sessions WHERE session_id = ? AND actor_id = ?");
            $stmt->execute([$session_id, $my_actor_id]);
            if (!$stmt->fetch()) {
                http_response_code(400);
                echo json_encode(["error" => "Session not found or not owned by this actor"]);
                break;
            }
        }

        $enc = \Crypto\Notebook::encrypt($description, $notebook_key);

        $stmt = $pdo->prepare(
            "INSERT INTO activities (actor_id, session_id, activity_type,
                 description_ciphertext, description_nonce, logged_at)
             VALUES (?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([
            $my_actor_id, $session_id, $activity_type,
            $enc["ciphertext"], $enc["nonce"],
            $logged_at ?? gmdate("Y-m-d H:i:s"),
        ]);
        $activity_id = (int)$pdo->lastInsertId();

        http_response_code(201);
        echo json_encode([
            "activity_id"   => $activity_id,
            "activity_type" => $activity_type,
            "session_id"    => $session_id,
            "logged_at"     => $logged_at ?? gmdate("Y-m-d H:i:s"),
        ]);
        break;

    case "DELETE":
        if (!$id_param) {
            http_response_code(400);
            echo json_encode(["error" => "activity_id required"]);
            break;
        }

        $stmt = $pdo->prepare(
            "DELETE FROM activities WHERE activity_id = ? AND actor_id = ?"
        );
        $stmt->execute([$id_param, $my_actor_id]);

        if ($stmt->rowCount() === 0) {
            http_response_code(404);
            echo json_encode(["error" => "Activity not found"]);
            break;
        }

        echo json_encode(["status" => "deleted", "activity_id" => $id_param]);
        break;

    default:
        http_response_code(405);
        echo json_encode(["error" => "Method not allowed"]);
}
