<?php
/**
 * Todo CRUD with status tracking and encrypted title/description
 *
 * GET    /todos              — list todos (with filters)
 * GET    /todos/{id}         — get single todo
 * POST   /todos              — create todo
 * PATCH  /todos/{id}         — update todo (status, title, description, etc.)
 * DELETE /todos/{id}         — delete todo
 *
 * GET    /todos/{id}/logs    — get status change history for a todo
 */

$method = $_SERVER["REQUEST_METHOD"];
$id_param = isset($segments[3]) ? (int)$segments[3] : null;
$sub_resource = $segments[4] ?? null;

$notebook_key = \Crypto\Notebook::deriveKey($raw_key);
$my_actor_id = (int)$auth_actor["actor_id"];

// Helper: decrypt a todo row
function decryptTodo(array $row, string $key): array {
    $title = \Crypto\Notebook::decrypt($row["title_ciphertext"], $row["title_nonce"], $key);
    $desc = null;
    if ($row["description_ciphertext"] !== null) {
        $dec = \Crypto\Notebook::decrypt(
            $row["description_ciphertext"], $row["description_nonce"], $key
        );
        $desc = $dec !== false ? $dec : "[DECRYPTION FAILED]";
    }
    return [
        "todo_id"     => (int)$row["todo_id"],
        "session_id"  => $row["session_id"] ? (int)$row["session_id"] : null,
        "title"       => $title !== false ? $title : "[DECRYPTION FAILED]",
        "description" => $desc,
        "status"      => $row["status"],
        "priority"    => (int)$row["priority"],
        "due_at"      => $row["due_at"],
        "created_at"  => $row["created_at"],
        "updated_at"  => $row["updated_at"],
    ];
}

// Sub-resource: /todos/{id}/logs
if ($id_param && $sub_resource === "logs" && $method === "GET") {
    // Verify ownership
    $stmt = $pdo->prepare("SELECT todo_id FROM todos WHERE todo_id = ? AND actor_id = ?");
    $stmt->execute([$id_param, $my_actor_id]);
    if (!$stmt->fetch()) {
        http_response_code(404);
        echo json_encode(["error" => "Todo not found"]);
        exit;
    }

    $stmt = $pdo->prepare(
        "SELECT log_id, old_status, new_status, note_ciphertext, note_nonce, logged_at
         FROM todo_logs WHERE todo_id = ? AND actor_id = ?
         ORDER BY logged_at ASC"
    );
    $stmt->execute([$id_param, $my_actor_id]);
    $rows = $stmt->fetchAll();

    $logs = [];
    foreach ($rows as $row) {
        $note = null;
        if ($row["note_ciphertext"] !== null) {
            $dec = \Crypto\Notebook::decrypt(
                $row["note_ciphertext"], $row["note_nonce"], $notebook_key
            );
            $note = $dec !== false ? $dec : "[DECRYPTION FAILED]";
        }
        $logs[] = [
            "log_id"     => (int)$row["log_id"],
            "old_status" => $row["old_status"],
            "new_status" => $row["new_status"],
            "note"       => $note,
            "logged_at"  => $row["logged_at"],
        ];
    }

    echo json_encode(["logs" => $logs, "todo_id" => $id_param]);
    exit;
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

            echo json_encode(decryptTodo($row, $notebook_key));
        } else {
            // GET /todos — list
            $status_filter = $_GET["status"] ?? null;
            $priority_filter = isset($_GET["priority"]) ? (int)$_GET["priority"] : null;
            $session_filter = isset($_GET["session_id"]) ? (int)$_GET["session_id"] : null;
            $limit = min((int)($_GET["limit"] ?? 50), 100);
            $offset = max((int)($_GET["offset"] ?? 0), 0);

            $where = "actor_id = ?";
            $params = [$my_actor_id];

            $valid_statuses = ["open", "in_progress", "done", "cancelled"];
            if ($status_filter !== null && in_array($status_filter, $valid_statuses)) {
                $where .= " AND status = ?";
                $params[] = $status_filter;
            }
            if ($priority_filter !== null) {
                $where .= " AND priority = ?";
                $params[] = $priority_filter;
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
                $todos[] = decryptTodo($row, $notebook_key);
            }

            // Total count
            $count_params = array_slice($params, 0, -2);
            $count_stmt = $pdo->prepare(
                "SELECT COUNT(*) as total FROM todos WHERE $where"
            );
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
        $session_id = isset($input["session_id"]) ? (int)$input["session_id"] : null;
        $priority = isset($input["priority"]) ? (int)$input["priority"] : 0;
        $due_at = $input["due_at"] ?? null;

        if (empty($title)) {
            http_response_code(400);
            echo json_encode(["error" => "title is required"]);
            break;
        }

        if ($priority < 0 || $priority > 3) {
            http_response_code(400);
            echo json_encode(["error" => "priority must be 0-3 (0=normal, 1=low, 2=medium, 3=high)"]);
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

        // Encrypt title and description
        $enc_title = \Crypto\Notebook::encrypt($title, $notebook_key);
        $enc_desc_ct = null;
        $enc_desc_nonce = null;
        if ($description !== null) {
            $enc_desc = \Crypto\Notebook::encrypt($description, $notebook_key);
            $enc_desc_ct = $enc_desc["ciphertext"];
            $enc_desc_nonce = $enc_desc["nonce"];
        }

        $pdo->beginTransaction();
        try {
            $stmt = $pdo->prepare(
                "INSERT INTO todos (actor_id, session_id, title_ciphertext, title_nonce,
                     description_ciphertext, description_nonce, priority, due_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            );
            $stmt->execute([
                $my_actor_id, $session_id,
                $enc_title["ciphertext"], $enc_title["nonce"],
                $enc_desc_ct, $enc_desc_nonce,
                $priority, $due_at,
            ]);
            $todo_id = (int)$pdo->lastInsertId();

            // Log initial status
            $stmt = $pdo->prepare(
                "INSERT INTO todo_logs (todo_id, actor_id, old_status, new_status)
                 VALUES (?, ?, NULL, 'open')"
            );
            $stmt->execute([$todo_id, $my_actor_id]);

            $pdo->commit();

            http_response_code(201);
            echo json_encode([
                "todo_id"    => $todo_id,
                "title"      => $title,
                "status"     => "open",
                "priority"   => $priority,
                "session_id" => $session_id,
                "due_at"     => $due_at,
            ]);
        } catch (\Exception $e) {
            $pdo->rollBack();
            http_response_code(500);
            echo json_encode(["error" => "Failed to create todo: " . $e->getMessage()]);
        }
        break;

    case "PATCH":
        if (!$id_param) {
            http_response_code(400);
            echo json_encode(["error" => "todo_id required"]);
            break;
        }

        // Verify ownership and get current status
        $stmt = $pdo->prepare(
            "SELECT todo_id, status FROM todos WHERE todo_id = ? AND actor_id = ?"
        );
        $stmt->execute([$id_param, $my_actor_id]);
        $todo = $stmt->fetch();

        if (!$todo) {
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
        if (array_key_exists("due_at", $input)) {
            $updates[] = "due_at = ?";
            $params[] = $input["due_at"];
        }
        if (array_key_exists("session_id", $input)) {
            $updates[] = "session_id = ?";
            $params[] = $input["session_id"];
        }

        $new_status = $input["status"] ?? null;
        $valid_statuses = ["open", "in_progress", "done", "cancelled"];
        if ($new_status !== null && in_array($new_status, $valid_statuses)) {
            $updates[] = "status = ?";
            $params[] = $new_status;
        }

        if (empty($updates)) {
            http_response_code(400);
            echo json_encode(["error" => "No fields to update"]);
            break;
        }

        $pdo->beginTransaction();
        try {
            $params[] = $id_param;
            $params[] = $my_actor_id;
            $stmt = $pdo->prepare(
                "UPDATE todos SET " . implode(", ", $updates) .
                " WHERE todo_id = ? AND actor_id = ?"
            );
            $stmt->execute($params);

            // Log status change if status changed
            if ($new_status !== null && $new_status !== $todo["status"]) {
                $note_ct = null;
                $note_nonce = null;
                if (isset($input["note"])) {
                    $enc = \Crypto\Notebook::encrypt($input["note"], $notebook_key);
                    $note_ct = $enc["ciphertext"];
                    $note_nonce = $enc["nonce"];
                }
                $stmt = $pdo->prepare(
                    "INSERT INTO todo_logs (todo_id, actor_id, old_status, new_status, note_ciphertext, note_nonce)
                     VALUES (?, ?, ?, ?, ?, ?)"
                );
                $stmt->execute([
                    $id_param, $my_actor_id,
                    $todo["status"], $new_status,
                    $note_ct, $note_nonce,
                ]);
            }

            $pdo->commit();
            echo json_encode(["status" => "updated", "todo_id" => $id_param]);
        } catch (\Exception $e) {
            $pdo->rollBack();
            http_response_code(500);
            echo json_encode(["error" => "Failed to update todo: " . $e->getMessage()]);
        }
        break;

    case "DELETE":
        if (!$id_param) {
            http_response_code(400);
            echo json_encode(["error" => "todo_id required"]);
            break;
        }

        $pdo->beginTransaction();
        try {
            // Delete logs first (foreign key)
            $stmt = $pdo->prepare("DELETE FROM todo_logs WHERE todo_id = ? AND actor_id = ?");
            $stmt->execute([$id_param, $my_actor_id]);

            $stmt = $pdo->prepare("DELETE FROM todos WHERE todo_id = ? AND actor_id = ?");
            $stmt->execute([$id_param, $my_actor_id]);

            if ($stmt->rowCount() === 0) {
                $pdo->rollBack();
                http_response_code(404);
                echo json_encode(["error" => "Todo not found"]);
                break;
            }

            $pdo->commit();
            echo json_encode(["status" => "deleted", "todo_id" => $id_param]);
        } catch (\Exception $e) {
            $pdo->rollBack();
            http_response_code(500);
            echo json_encode(["error" => "Failed to delete todo: " . $e->getMessage()]);
        }
        break;

    default:
        http_response_code(405);
        echo json_encode(["error" => "Method not allowed"]);
}
