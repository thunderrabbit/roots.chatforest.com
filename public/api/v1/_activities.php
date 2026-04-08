<?php
/**
 * Activity endpoints — encrypted activity logging with stats
 *
 *   GET    /activities              — list activities
 *   POST   /activities              — log an activity
 *   GET    /activities/{id}         — get single activity
 *   DELETE /activities/{id}         — delete activity
 *   GET    /activities/stats        — activity stats (counts by type/period)
 */

$method = $_SERVER["REQUEST_METHOD"];
$sub_or_id = $segments[3] ?? null;
$notebook_key = \Crypto\Notebook::deriveKey($raw_key);
$my_actor_id = (int)$auth_actor["actor_id"];

// ─── STATS ───────────────────────────────────────────────────────────
if ($sub_or_id === "stats" && $method === "GET") {
    $since = $_GET["since"] ?? gmdate("Y-m-d", strtotime("-30 days"));
    $until = $_GET["until"] ?? gmdate("Y-m-d H:i:s");

    // Counts by activity_type
    $stmt = $pdo->prepare(
        "SELECT activity_type, COUNT(*) as count
         FROM activities
         WHERE actor_id = ? AND logged_at >= ? AND logged_at <= ?
         GROUP BY activity_type
         ORDER BY count DESC"
    );
    $stmt->execute([$my_actor_id, $since, $until]);
    $by_type = $stmt->fetchAll();

    // Counts by day
    $stmt = $pdo->prepare(
        "SELECT DATE(logged_at) as day, COUNT(*) as count
         FROM activities
         WHERE actor_id = ? AND logged_at >= ? AND logged_at <= ?
         GROUP BY DATE(logged_at)
         ORDER BY day DESC"
    );
    $stmt->execute([$my_actor_id, $since, $until]);
    $by_day = $stmt->fetchAll();

    // Total
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) as total FROM activities
         WHERE actor_id = ? AND logged_at >= ? AND logged_at <= ?"
    );
    $stmt->execute([$my_actor_id, $since, $until]);
    $total = (int)$stmt->fetch()["total"];

    echo json_encode([
        "total"   => $total,
        "since"   => $since,
        "until"   => $until,
        "by_type" => $by_type,
        "by_day"  => $by_day,
    ]);
    exit;
}

$id_param = $sub_or_id !== null ? (int)$sub_or_id : null;

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

            $desc = \Crypto\Notebook::decrypt(
                $row["description_ciphertext"], $row["description_nonce"], $notebook_key
            );

            echo json_encode([
                "activity_id"   => (int)$row["activity_id"],
                "session_id"    => $row["session_id"] ? (int)$row["session_id"] : null,
                "activity_type" => $row["activity_type"],
                "description"   => $desc !== false ? $desc : "[DECRYPTION FAILED]",
                "logged_at"     => $row["logged_at"],
                "created_at"    => $row["created_at"],
            ]);
        } else {
            // GET /activities — list
            $limit = min((int)($_GET["limit"] ?? 50), 100);
            $offset = max((int)($_GET["offset"] ?? 0), 0);
            $type_filter = $_GET["type"] ?? null;
            $session_filter = isset($_GET["session_id"]) ? (int)$_GET["session_id"] : null;
            $since = $_GET["since"] ?? null;
            $until = $_GET["until"] ?? null;

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
                $desc = \Crypto\Notebook::decrypt(
                    $row["description_ciphertext"], $row["description_nonce"], $notebook_key
                );
                $activities[] = [
                    "activity_id"   => (int)$row["activity_id"],
                    "session_id"    => $row["session_id"] ? (int)$row["session_id"] : null,
                    "activity_type" => $row["activity_type"],
                    "description"   => $desc !== false ? $desc : "[DECRYPTION FAILED]",
                    "logged_at"     => $row["logged_at"],
                ];
            }

            $count_params = array_slice($params, 0, -2);
            $count_stmt = $pdo->prepare("SELECT COUNT(*) as total FROM activities WHERE $where");
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
        $activity_type = $input["type"] ?? "general";
        $session_id = isset($input["session_id"]) ? (int)$input["session_id"] : null;
        $logged_at = $input["logged_at"] ?? gmdate("Y-m-d H:i:s");

        if (empty($description)) {
            http_response_code(400);
            echo json_encode(["error" => "description is required"]);
            break;
        }

        if (!preg_match('/^[a-z0-9_]{1,50}$/', $activity_type)) {
            http_response_code(400);
            echo json_encode(["error" => "type must be lowercase alphanumeric with underscores, max 50 chars"]);
            break;
        }

        // Verify session ownership if provided
        if ($session_id !== null) {
            $check = $pdo->prepare("SELECT session_id FROM sessions WHERE session_id = ? AND actor_id = ?");
            $check->execute([$session_id, $my_actor_id]);
            if (!$check->fetch()) {
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
            $enc["ciphertext"], $enc["nonce"], $logged_at,
        ]);
        $activity_id = (int)$pdo->lastInsertId();

        http_response_code(201);
        echo json_encode([
            "activity_id"   => $activity_id,
            "activity_type" => $activity_type,
            "logged_at"     => $logged_at,
        ]);
        break;

    case "DELETE":
        if (!$id_param) {
            http_response_code(400);
            echo json_encode(["error" => "activity_id required"]);
            break;
        }

        $stmt = $pdo->prepare("DELETE FROM activities WHERE activity_id = ? AND actor_id = ?");
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
