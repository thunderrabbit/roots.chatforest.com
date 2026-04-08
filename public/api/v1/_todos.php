<?php
/**
 * Todo endpoints — encrypted task tracking with status logs
 *
 *   GET    /todos              — list todos
 *   POST   /todos              — create todo
 *   GET    /todos/{id}         — get single todo (with logs)
 *   PATCH  /todos/{id}         — update todo (status, title, etc.)
 *   DELETE /todos/{id}         — delete todo
 */

$method = $_SERVER["REQUEST_METHOD"];
$id_param = isset($segments[3]) ? (int)$segments[3] : null;
$sub = $segments[4] ?? null;
$notebook_key = \Crypto\Notebook::deriveKey($raw_key);
$my_actor_id = (int)$auth_actor["actor_id"];

$valid_statuses = ["open", "in_progress", "done", "cancelled"];

// Helper to format a todo row
function format_todo($row, $notebook_key) {
    $title = \Crypto\Notebook::decrypt(
        $row["title_ciphertext"], $row["title_nonce"], $notebook_key
    );

    $todo = [
        "todo_id"    => (int)$row["todo_id"],
        "title"      => $title !== false ? $title : "[DECRYPTION FAILED]",
        "status"     => $row["status"],
        "priority"   => (int)$row["priority"],
        "session_id" => $row["session_id"] ? (int)$row["session_id"] : null,
        "due_at"     => $row["due_at"],
        "created_at" => $row["created_at"],
        "updated_at" => $row["updated_at"],
    ];

    if ($row["description_ciphertext"] !== null) {
        $desc = \Crypto\Notebook::decrypt(
            $row["description_ciphertext"], $row["description_nonce"], $notebook_key
        );
        $todo["description"] = $desc !== false ? $desc : "[DECRYPTION FAILED]";
    }

    return $todo;
}

switch ($method) {
    case "GET":
        if ($id_param) {
            // GET /todos/{id}
            $stmt = $pdo->prepare(
                "SELECT todo_id, session_id, title_ciphertext, title_nonce,
                        description_ciphertext, description_nonce,
                        status, priority, due_at, created_at, updated_at
                 FROM todos WHERE todo_id = ? AND actor_id = ?"
            );
            $stmt->execute([$id_param, $my_actor_id]);
            $row = $stmt->fetch();

            if (!$row) {
                http_response_code(404);
                echo json_encode(["error" => "Todo not found"]);
                break;
            }

            $todo = format_todo($row, $notebook_key);

            // Include status logs if sub-resource is 'logs' or always
            if ($sub === "logs" || $sub === null) {
                $log_stmt = $pdo->prepare(
                    "SELECT log_id, old_status, new_status, note_ciphertext, note_nonce, logged_at
                     FROM todo_logs WHERE todo_id = ? AND actor_id = ?
                     ORDER BY logged_at ASC"
                );
                $log_stmt->execute([$id_param, $my_actor_id]);
                $log_rows = $log_stmt->fetchAll();

                $logs = [];
                foreach ($log_rows as $lr) {
                    $log = [
                        "log_id"     => (int)$lr["log_id"],
                        "old_status" => $lr["old_status"],
                        "new_status" => $lr["new_status"],
                        "logged_at"  => $lr["logged_at"],
                    ];
                    if ($lr["note_ciphertext"] !== null) {
                        $note = \Crypto\Notebook::decrypt(
                            $lr["note_ciphertext"], $lr["note_nonce"], $notebook_key
                        );
                        $log["note"] = $note !== false ? $note : "[DECRYPTION FAILED]";
                    }
                    $logs[] = $log;
                }
                $todo["logs"] = $logs;
            }

            echo json_encode($todo);
        } else {
            // GET /todos — list
            $limit = min((int)($_GET["limit"] ?? 50), 100);
            $offset = max((int)($_GET["offset"] ?? 0), 0);
            $status_filter = $_GET["status"] ?? null;
            $session_filter = isset($_GET["session_id"]) ? (int)$_GET["session_id"] : null;

            $where = "actor_id = ?";
            $params = [$my_actor_id];

            if ($status_filter !== null) {
                $where .= " AND status = ?";
                $params[] = $status_filter;
            }
            if ($session_filter !== null) {
                $where .= " AND session_id = ?";
                $params[] = $session_filter;
            }

            $params[] = $limit;
            $params[] = $offset;

            $stmt = $pdo->prepare(
                "SELECT todo_id, session_id, title_ciphertext, title_nonce,
                        description_ciphertext, description_nonce,
                        status, priority, due_at, created_at, updated_at
                 FROM todos WHERE $where
                 ORDER BY priority DESC, created_at DESC
                 LIMIT ? OFFSET ?"
            );
            $stmt->execute($params);
            $rows = $stmt->fetchAll();

            $todos = [];
            foreach ($rows as $row) {
                $todos[] = format_todo($row, $notebook_key);
            }

            $count_params = array_slice($params, 0, -2);
            $count_stmt = $pdo->prepare("SELECT COUNT(*) as total FROM todos WHERE $where");
            $count_stmt->execute($count_params);
            $total = (int)$count_stmt->fetch()["total"];

            echo json_encode([
                "todos"  => $todos,
                "total"  => $total,
                "limit"  => $limit,
                "offset" => $offset,
            ]);
        }
        break;

    case "POST":
        $input = json_decode(file_get_contents("php://input"), true);
        $title = $input["title"] ?? "";
        $description = $input["description"] ?? null;
        $status = $input["status"] ?? "open";
        $priority = (int)($input["priority"] ?? 0);
        $due_at = $input["due_at"] ?? null;
        $session_id = isset($input["session_id"]) ? (int)$input["session_id"] : null;

        if (empty($title)) {
            http_response_code(400);
            echo json_encode(["error" => "title is required"]);
            break;
        }

        if (!in_array($status, $valid_statuses)) {
            http_response_code(400);
            echo json_encode(["error" => "status must be one of: " . implode(", ", $valid_statuses)]);
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

        $enc_title = \Crypto\Notebook::encrypt($title, $notebook_key);
        $enc_desc_ct = null;
        $enc_desc_nonce = null;
        if ($description !== null) {
            $enc_desc = \Crypto\Notebook::encrypt($description, $notebook_key);
            $enc_desc_ct = $enc_desc["ciphertext"];
            $enc_desc_nonce = $enc_desc["nonce"];
        }

        $stmt = $pdo->prepare(
            "INSERT INTO todos (actor_id, session_id, title_ciphertext, title_nonce,
                    description_ciphertext, description_nonce, status, priority, due_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([
            $my_actor_id, $session_id,
            $enc_title["ciphertext"], $enc_title["nonce"],
            $enc_desc_ct, $enc_desc_nonce,
            $status, $priority, $due_at,
        ]);
        $todo_id = (int)$pdo->lastInsertId();

        // Log initial status
        $log_stmt = $pdo->prepare(
            "INSERT INTO todo_logs (todo_id, actor_id, old_status, new_status) VALUES (?, ?, NULL, ?)"
        );
        $log_stmt->execute([$todo_id, $my_actor_id, $status]);

        http_response_code(201);
        echo json_encode([
            "todo_id"  => $todo_id,
            "title"    => $title,
            "status"   => $status,
            "priority" => $priority,
        ]);
        break;

    case "PATCH":
        if (!$id_param) {
            http_response_code(400);
            echo json_encode(["error" => "todo_id required"]);
            break;
        }

        $stmt = $pdo->prepare("SELECT todo_id, status FROM todos WHERE todo_id = ? AND actor_id = ?");
        $stmt->execute([$id_param, $my_actor_id]);
        $existing = $stmt->fetch();
        if (!$existing) {
            http_response_code(404);
            echo json_encode(["error" => "Todo not found"]);
            break;
        }

        $input = json_decode(file_get_contents("php://input"), true);
        $updates = [];
        $params = [];

        if (isset($input["title"])) {
            $enc = \Crypto\Notebook::encrypt($input["title"], $notebook_key);
            $updates[] = "title_ciphertext = ?, title_nonce = ?";
            $params[] = $enc["ciphertext"];
            $params[] = $enc["nonce"];
        }
        if (array_key_exists("description", $input)) {
            if ($input["description"] === null) {
                $updates[] = "description_ciphertext = NULL, description_nonce = NULL";
            } else {
                $enc = \Crypto\Notebook::encrypt($input["description"], $notebook_key);
                $updates[] = "description_ciphertext = ?, description_nonce = ?";
                $params[] = $enc["ciphertext"];
                $params[] = $enc["nonce"];
            }
        }
        if (isset($input["priority"])) {
            $updates[] = "priority = ?";
            $params[] = (int)$input["priority"];
        }
        if (isset($input["due_at"])) {
            $updates[] = "due_at = ?";
            $params[] = $input["due_at"];
        }
        if (isset($input["status"])) {
            if (!in_array($input["status"], $valid_statuses)) {
                http_response_code(400);
                echo json_encode(["error" => "Invalid status"]);
                break;
            }
            $updates[] = "status = ?";
            $params[] = $input["status"];

            // Log status change
            $note_ct = null;
            $note_nonce = null;
            if (isset($input["note"])) {
                $enc_note = \Crypto\Notebook::encrypt($input["note"], $notebook_key);
                $note_ct = $enc_note["ciphertext"];
                $note_nonce = $enc_note["nonce"];
            }
            $log_stmt = $pdo->prepare(
                "INSERT INTO todo_logs (todo_id, actor_id, old_status, new_status, note_ciphertext, note_nonce)
                 VALUES (?, ?, ?, ?, ?, ?)"
            );
            $log_stmt->execute([
                $id_param, $my_actor_id,
                $existing["status"], $input["status"],
                $note_ct, $note_nonce,
            ]);
        }

        if (empty($updates)) {
            http_response_code(400);
            echo json_encode(["error" => "No fields to update"]);
            break;
        }

        $params[] = $id_param;
        $params[] = $my_actor_id;
        $stmt = $pdo->prepare(
            "UPDATE todos SET " . implode(", ", $updates) .
            " WHERE todo_id = ? AND actor_id = ?"
        );
        $stmt->execute($params);

        echo json_encode(["status" => "updated", "todo_id" => $id_param]);
        break;

    case "DELETE":
        if (!$id_param) {
            http_response_code(400);
            echo json_encode(["error" => "todo_id required"]);
            break;
        }

        // Delete logs first (FK constraint)
        $pdo->prepare("DELETE FROM todo_logs WHERE todo_id = ?")->execute([$id_param]);

        $stmt = $pdo->prepare("DELETE FROM todos WHERE todo_id = ? AND actor_id = ?");
        $stmt->execute([$id_param, $my_actor_id]);

        if ($stmt->rowCount() === 0) {
            http_response_code(404);
            echo json_encode(["error" => "Todo not found"]);
            break;
        }

        echo json_encode(["status" => "deleted", "todo_id" => $id_param]);
        break;

    default:
        http_response_code(405);
        echo json_encode(["error" => "Method not allowed"]);
}
