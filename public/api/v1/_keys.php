<?php
/**
 * API Key management endpoints
 *
 * GET    /keys              — list keys for caller's account (hashes redacted)
 * POST   /keys              — generate new key for an actor
 * DELETE /keys/{key_id}     — revoke a key
 *
 * POST   /bootstrap         — create account + actor + first API key (no auth required)
 *                             This is handled specially in the router.
 */

$method = $_SERVER['REQUEST_METHOD'];
$key_id_param = isset($segments[3]) ? (int)$segments[3] : null;

switch ($method) {
    case 'GET':
        // List all keys for the authenticated account
        $stmt = $pdo->prepare(
            "SELECT k.key_id, k.actor_id, a.name as actor_name, k.key_prefix, k.label,
                    k.is_active, k.created_at, k.last_used, k.expires_at
             FROM api_keys k
             JOIN actors a ON a.actor_id = k.actor_id
             WHERE k.account_id = ?
             ORDER BY k.key_id DESC"
        );
        $stmt->execute([$auth_actor['account_id']]);
        echo json_encode($stmt->fetchAll());
        break;

    case 'POST':
        // Generate a new API key for an actor
        $input = json_decode(file_get_contents('php://input'), true);
        $target_actor_id = $input['actor_id'] ?? null;
        $label = $input['label'] ?? null;

        if (!$target_actor_id) {
            http_response_code(400);
            echo json_encode(['error' => 'actor_id is required']);
            break;
        }

        // Verify actor belongs to caller's account
        $stmt = $pdo->prepare(
            "SELECT actor_id FROM actors WHERE actor_id = ? AND account_id = ? AND is_active = 1"
        );
        $stmt->execute([$target_actor_id, $auth_actor['account_id']]);
        if (!$stmt->fetch()) {
            http_response_code(403);
            echo json_encode(['error' => 'Actor not in your account or inactive']);
            break;
        }

        // Generate the raw key
        $raw_key = bin2hex(random_bytes(32)); // 64 hex chars
        $key_hash = hash('sha256', $raw_key);
        $key_prefix = substr($raw_key, 0, 8);

        // Derive encryption keypair from key
        $keys = \Crypto\Inbox::deriveKeypair($raw_key);

        $pdo->beginTransaction();
        try {
            // Store key
            $stmt = $pdo->prepare(
                "INSERT INTO api_keys (account_id, actor_id, api_key_hash, key_prefix, label)
                 VALUES (?, ?, ?, ?, ?)"
            );
            $stmt->execute([$auth_actor['account_id'], $target_actor_id, $key_hash, $key_prefix, $label]);
            $new_key_id = (int)$pdo->lastInsertId();

            // Update actor's public key (latest key wins)
            $stmt = $pdo->prepare(
                "UPDATE actors SET public_key = ? WHERE actor_id = ?"
            );
            $stmt->execute([$keys['public_key'], $target_actor_id]);

            $pdo->commit();
        } catch (\Exception $e) {
            $pdo->rollBack();
            http_response_code(500);
            echo json_encode(['error' => 'Failed to create key: ' . $e->getMessage()]);
            break;
        }

        http_response_code(201);
        echo json_encode([
            'key_id' => $new_key_id,
            'actor_id' => (int)$target_actor_id,
            'api_key' => $raw_key,
            'key_prefix' => $key_prefix,
            'public_key_hex' => bin2hex($keys['public_key']),
            'warning' => 'Store this API key securely — it cannot be retrieved again'
        ]);
        break;

    case 'DELETE':
        if (!$key_id_param) {
            http_response_code(400);
            echo json_encode(['error' => 'Key ID required']);
            break;
        }
        $stmt = $pdo->prepare(
            "UPDATE api_keys SET is_active = 0 WHERE key_id = ? AND account_id = ?"
        );
        $stmt->execute([$key_id_param, $auth_actor['account_id']]);
        if ($stmt->rowCount() === 0) {
            http_response_code(404);
            echo json_encode(['error' => 'Key not found']);
            break;
        }
        echo json_encode(['status' => 'revoked', 'key_id' => $key_id_param]);
        break;

    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
}
