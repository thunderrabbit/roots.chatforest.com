<?php
/**
 * Actor CRUD endpoints
 *
 * GET    /actors          — list actors visible to caller
 * GET    /actors/{id}     — get single actor
 * POST   /actors          — create actor (account owner only)
 * PATCH  /actors/{id}     — update actor
 * DELETE /actors/{id}     — deactivate actor
 *
 * POST   /actors/{id}/visibility  — add visibility link
 * DELETE /actors/{id}/visibility/{target_id} — remove visibility link
 */

$method = $_SERVER['REQUEST_METHOD'];
$actor_id_param = isset($segments[3]) ? (int)$segments[3] : null;
$sub_resource = $segments[4] ?? null;

switch ($method) {
    case 'GET':
        if ($actor_id_param) {
            // GET /actors/{id}
            $stmt = $pdo->prepare(
                "SELECT actor_id, account_id, name, actor_type, can_read_inbox, can_write_inbox,
                        HEX(public_key) as public_key_hex, created_at, is_active
                 FROM actors WHERE actor_id = ? AND account_id = ?"
            );
            $stmt->execute([$actor_id_param, $auth_actor['account_id']]);
            $actor = $stmt->fetch();
            if (!$actor) {
                http_response_code(404);
                echo json_encode(['error' => 'Actor not found']);
                break;
            }
            echo json_encode($actor);
        } else {
            // GET /actors — list actors in the same account
            $stmt = $pdo->prepare(
                "SELECT actor_id, name, actor_type, can_read_inbox, can_write_inbox,
                        HEX(public_key) as public_key_hex, created_at, is_active
                 FROM actors WHERE account_id = ? ORDER BY actor_id"
            );
            $stmt->execute([$auth_actor['account_id']]);
            echo json_encode($stmt->fetchAll());
        }
        break;

    case 'POST':
        if ($actor_id_param && $sub_resource === 'visibility') {
            // POST /actors/{id}/visibility — add visibility link
            $input = json_decode(file_get_contents('php://input'), true);
            $target_id = $input['target_actor_id'] ?? null;
            if (!$target_id) {
                http_response_code(400);
                echo json_encode(['error' => 'target_actor_id required']);
                break;
            }
            // Verify both actors belong to same account
            $stmt = $pdo->prepare(
                "SELECT actor_id FROM actors WHERE actor_id IN (?, ?) AND account_id = ?"
            );
            $stmt->execute([$actor_id_param, $target_id, $auth_actor['account_id']]);
            if ($stmt->rowCount() < 2) {
                http_response_code(403);
                echo json_encode(['error' => 'Both actors must be in your account']);
                break;
            }
            $stmt = $pdo->prepare(
                "INSERT IGNORE INTO actor_visibility (watcher_actor_id, watched_actor_id) VALUES (?, ?)"
            );
            $stmt->execute([$actor_id_param, $target_id]);
            echo json_encode(['status' => 'ok', 'watcher' => $actor_id_param, 'watched' => (int)$target_id]);
            break;
        }

        // POST /actors — create new actor
        $input = json_decode(file_get_contents('php://input'), true);
        $name = trim($input['name'] ?? '');
        $type = $input['actor_type'] ?? 'agent';

        if (empty($name)) {
            http_response_code(400);
            echo json_encode(['error' => 'name is required']);
            break;
        }
        if (!in_array($type, ['agent', 'human', 'system'])) {
            http_response_code(400);
            echo json_encode(['error' => 'actor_type must be agent, human, or system']);
            break;
        }

        $stmt = $pdo->prepare(
            "INSERT INTO actors (account_id, name, actor_type) VALUES (?, ?, ?)"
        );
        $stmt->execute([$auth_actor['account_id'], $name, $type]);
        $new_id = (int)$pdo->lastInsertId();

        echo json_encode([
            'actor_id' => $new_id,
            'name' => $name,
            'actor_type' => $type,
            'note' => 'Generate an API key for this actor to enable encryption keypair'
        ]);
        http_response_code(201);
        break;

    case 'PATCH':
        if (!$actor_id_param) {
            http_response_code(400);
            echo json_encode(['error' => 'Actor ID required']);
            break;
        }
        $input = json_decode(file_get_contents('php://input'), true);
        $fields = [];
        $params = [];
        foreach (['name', 'can_read_inbox', 'can_write_inbox'] as $f) {
            if (isset($input[$f])) {
                $fields[] = "$f = ?";
                $params[] = $input[$f];
            }
        }
        if (empty($fields)) {
            http_response_code(400);
            echo json_encode(['error' => 'No updatable fields provided']);
            break;
        }
        $params[] = $actor_id_param;
        $params[] = $auth_actor['account_id'];
        $stmt = $pdo->prepare(
            "UPDATE actors SET " . implode(', ', $fields) . " WHERE actor_id = ? AND account_id = ?"
        );
        $stmt->execute($params);
        if ($stmt->rowCount() === 0) {
            http_response_code(404);
            echo json_encode(['error' => 'Actor not found or no changes']);
            break;
        }
        echo json_encode(['status' => 'updated', 'actor_id' => $actor_id_param]);
        break;

    case 'DELETE':
        if ($actor_id_param && $sub_resource === 'visibility') {
            // DELETE /actors/{id}/visibility/{target_id}
            $target_id = isset($segments[5]) ? (int)$segments[5] : null;
            if (!$target_id) {
                http_response_code(400);
                echo json_encode(['error' => 'Target actor ID required in URL']);
                break;
            }
            $stmt = $pdo->prepare(
                "DELETE FROM actor_visibility WHERE watcher_actor_id = ? AND watched_actor_id = ?"
            );
            $stmt->execute([$actor_id_param, $target_id]);
            echo json_encode(['status' => 'ok', 'removed' => $stmt->rowCount()]);
            break;
        }

        if (!$actor_id_param) {
            http_response_code(400);
            echo json_encode(['error' => 'Actor ID required']);
            break;
        }
        $stmt = $pdo->prepare(
            "UPDATE actors SET is_active = 0 WHERE actor_id = ? AND account_id = ?"
        );
        $stmt->execute([$actor_id_param, $auth_actor['account_id']]);
        echo json_encode(['status' => 'deactivated', 'actor_id' => $actor_id_param]);
        break;

    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
}
