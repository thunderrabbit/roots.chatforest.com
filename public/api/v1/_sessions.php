<?php
/**
 * Session endpoints — track work sessions with encrypted notes
 *
 *   GET    /sessions              — list sessions
 *   POST   /sessions              — start a new session
 *   GET    /sessions/{id}         — get single session
 *   PATCH  /sessions/{id}         — update session (end it, add notes)
 *   DELETE /sessions/{id}         — delete session
 */

$method = $_SERVER["REQUEST_METHOD"];
$id_param = isset($segments[3]) ? (int)$segments[3] : null;
$notebook_key = \Crypto\Notebook::deriveKey($raw_key);
$my_actor_id = (int)$auth_actor["actor_id"];

switch ($method) {
    case "GET":
        if ($id_param) {
            // GET /sessions/{id}
            $stmt = $pdo->prepare(
                "SELECT session_id, status, notes_ciphertext, notes_nonce,
                        started_at, ended_at, created_at
                 FROM sessions WHERE session_id = ? AND actor_id = ?"
            );
            $stmt->execute([$id_param, $my_actor_id]);
            $row = $stmt->fetch();

            if (!$row) {
                http_response_code(404);
                echo json_encode(["error" => "Session not found"]);
                break;
            }

            $session = [
                "session_id" => (int)$row["session_id"],
                "status"     => $row["status"],
                "started_at" => $row["started_at"],
                "ended_at"   => $row["ended_at"],
                "created_at" => $row["created_at"],
            ];

            if ($row["notes_ciphertext"] !== null) {
                $notes = \Crypto\Notebook::decrypt(
                    $row["notes_ciphertext"], $row["notes_nonce"], $notebook_key
                );
                $session["notes"] = $notes !== false ? $notes : "[DECRYPTION FAILED]";
            }

            echo json_encode($session);
        } else {
            // GET /sessions — list
            $limit = min((int)($_GET["limit"] ?? 50), 100);
            $offset = max((int)($_GET["offset"] ?? 0), 0);
            $status_filter = $_GET["status"] ?? null;

            $where = "actor_id = ?";
            $params = [$my_actor_id];

            if ($status_filter !== null) {
                $where .= " AND status = ?";
                $params[] = $status_filter;
            }

            $params[] = $limit;
            $params[] = $offset;

            $stmt = $pdo->prepare(
                "SELECT session_id, status, notes_ciphertext, notes_nonce,
                        started_at, ended_at, created_at
                 FROM sessions WHERE $where
                 ORDER BY started_at DESC LIMIT ? OFFSET ?"
            );
            $stmt->execute($params);
            $rows = $stmt->fetchAll();

            $sessions = [];
            foreach ($rows as $row) {
                $s = [
                    "session_id" => (int)$row["session_id"],
                    "status"     => $row["status"],
                    "started_at" => $row["started_at"],
                    "ended_at"   => $row["ended_at"],
                ];
                if ($row["notes_ciphertext"] !== null) {
                    $notes = \Crypto\Notebook::decrypt(
                        $row["notes_ciphertext"], $row["notes_nonce"], $notebook_key
                    );
                    $s["notes"] = $notes !== false ? $notes : "[DECRYPTION FAILED]";
                }
                $sessions[] = $s;
            }

            // Total count
            $count_params = array_slice($params, 0, -2);
            $count_stmt = $pdo->prepare(
                "SELECT COUNT(*) as total FROM sessions WHERE $where"
            );
            $count_stmt->execute($count_params);
            $total = (int)$count_stmt->fetch()["total"];

            echo json_encode([
                "sessions" => $sessions,
                "total"    => $total,
                "limit"    => $limit,
                "offset"   => $offset,
            ]);
        }
        break;

    case "POST":
        $input = json_decode(file_get_contents("php://input"), true);
        $notes = $input["notes"] ?? null;
        $started_at = $input["started_at"] ?? gmdate("Y-m-d H:i:s");

        $enc_notes_ct = null;
        $enc_notes_nonce = null;
        if ($notes !== null) {
            $enc = \Crypto\Notebook::encrypt($notes, $notebook_key);
            $enc_notes_ct = $enc["ciphertext"];
            $enc_notes_nonce = $enc["nonce"];
        }

        $stmt = $pdo->prepare(
            "INSERT INTO sessions (actor_id, notes_ciphertext, notes_nonce, started_at)
             VALUES (?, ?, ?, ?)"
        );
        $stmt->execute([$my_actor_id, $enc_notes_ct, $enc_notes_nonce, $started_at]);
        $session_id = (int)$pdo->lastInsertId();

        http_response_code(201);
        echo json_encode([
            "session_id" => $session_id,
            "status"     => "active",
            "started_at" => $started_at,
        ]);
        break;

    case "PATCH":
        if (!$id_param) {
            http_response_code(400);
            echo json_encode(["error" => "session_id required"]);
            break;
        }

        // Verify ownership
        $stmt = $pdo->prepare("SELECT session_id, status FROM sessions WHERE session_id = ? AND actor_id = ?");
        $stmt->execute([$id_param, $my_actor_id]);
        $existing = $stmt->fetch();
        if (!$existing) {
            http_response_code(404);
            echo json_encode(["error" => "Session not found"]);
            break;
        }

        $input = json_decode(file_get_contents("php://input"), true);
        $updates = [];
        $params = [];

        if (isset($input["action"]) && $input["action"] === "end") {
            if ($existing["status"] === "ended") {
                http_response_code(409);
                echo json_encode(["error" => "Session already ended"]);
                break;
            }
            $updates[] = "status = 'ended'";
            $updates[] = "ended_at = ?";
            $params[] = $input["ended_at"] ?? gmdate("Y-m-d H:i:s");
        }

        if (array_key_exists("notes", $input)) {
            if ($input["notes"] === null) {
                $updates[] = "notes_ciphertext = NULL, notes_nonce = NULL";
            } else {
                $enc = \Crypto\Notebook::encrypt($input["notes"], $notebook_key);
                $updates[] = "notes_ciphertext = ?, notes_nonce = ?";
                $params[] = $enc["ciphertext"];
                $params[] = $enc["nonce"];
            }
        }

        if (empty($updates)) {
            http_response_code(400);
            echo json_encode(["error" => "No fields to update. Use {\"action\": \"end\"} or {\"notes\": \"...\"}"]);
            break;
        }

        $params[] = $id_param;
        $params[] = $my_actor_id;
        $stmt = $pdo->prepare(
            "UPDATE sessions SET " . implode(", ", $updates) .
            " WHERE session_id = ? AND actor_id = ?"
        );
        $stmt->execute($params);

        echo json_encode(["status" => "updated", "session_id" => $id_param]);
        break;

    case "DELETE":
        if (!$id_param) {
            http_response_code(400);
            echo json_encode(["error" => "session_id required"]);
            break;
        }

        $stmt = $pdo->prepare("DELETE FROM sessions WHERE session_id = ? AND actor_id = ?");
        $stmt->execute([$id_param, $my_actor_id]);

        if ($stmt->rowCount() === 0) {
            http_response_code(404);
            echo json_encode(["error" => "Session not found"]);
            break;
        }

        echo json_encode(["status" => "deleted", "session_id" => $id_param]);
        break;

    default:
        http_response_code(405);
        echo json_encode(["error" => "Method not allowed"]);
}
