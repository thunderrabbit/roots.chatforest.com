<?php
/**
 * API Key management endpoints
 *
 * GET    /keys              — list keys for caller's account (hashes redacted)
 * POST   /keys              — generate new key for an actor
 * DELETE /keys/{key_id}     — revoke a key
 *
 * POST   /keys/rotate       — rotate key: deactivate old, generate new, warn about message loss
 */

$method = $_SERVER['REQUEST_METHOD'];
$key_id_param = isset($segments[3]) ? (int)$segments[3] : null;
$sub_resource = $segments[3] ?? null;

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
        if ($sub_resource === 'rotate') {
            // POST /keys/rotate — rotate the calling key
            $input = json_decode(file_get_contents('php://input'), true);
            $label = $input['label'] ?? 'rotated key';
            $confirm = $input['confirm_message_loss'] ?? false;

            // Check if actor has any encrypted inbox messages
            $msg_stmt = $pdo->prepare(
                "SELECT COUNT(*) as cnt FROM message_recipients WHERE recipient_actor_id = ?"
            );
            $msg_stmt->execute([$auth_actor['actor_id']]);
            $msg_count = (int)$msg_stmt->fetch()['cnt'];

            if ($msg_count > 0 && !$confirm) {
                http_response_code(409);
                echo json_encode([
                    'error' => 'Key rotation will make ' . $msg_count . ' existing inbox messages permanently undecryptable',
                    'action_required' => 'Set confirm_message_loss: true to proceed',
                    'messages_at_risk' => $msg_count,
                ]);
                break;
            }

            // Generate new key
            $raw_key = bin2hex(random_bytes(32));
            $key_hash = hash('sha256', $raw_key);
            $key_prefix = substr($raw_key, 0, 8);
            $keys = \Crypto\Inbox::deriveKeypair($raw_key);

            $pdo->beginTransaction();
            try {
                // Deactivate all existing keys for this actor
                $pdo->prepare(
                    "UPDATE api_keys SET is_active = 0 WHERE actor_id = ? AND account_id = ?"
                )->execute([$auth_actor['actor_id'], $auth_actor['account_id']]);

                // Create new key
                $stmt = $pdo->prepare(
                    "INSERT INTO api_keys (account_id, actor_id, api_key_hash, key_prefix, label)
                     VALUES (?, ?, ?, ?, ?)"
                );
                $stmt->execute([$auth_actor['account_id'], $auth_actor['actor_id'], $key_hash, $key_prefix, $label]);
                $new_key_id = (int)$pdo->lastInsertId();

                // Update actor's public key
                $pdo->prepare(
                    "UPDATE actors SET public_key = ? WHERE actor_id = ?"
                )->execute([$keys['public_key'], $auth_actor['actor_id']]);

                $pdo->commit();
            } catch (\Exception $e) {
                $pdo->rollBack();
                http_response_code(500);
                echo json_encode(['error' => 'Key rotation failed']);
                break;
            }

            http_response_code(201);
            echo json_encode([
                'key_id' => $new_key_id,
                'actor_id' => (int)$auth_actor['actor_id'],
                'api_key' => $raw_key,
                'key_prefix' => $key_prefix,
                'public_key_hex' => bin2hex($keys['public_key']),
                'messages_orphaned' => $msg_count,
                'warning' => 'Store this API key securely — it cannot be retrieved again. Old messages are now undecryptable.',
            ]);
            break;
        }

        // POST /keys — generate a new key for an actor
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
            "SELECT actor_id, public_key FROM actors WHERE actor_id = ? AND account_id = ? AND is_active = 1"
        );
        $stmt->execute([$target_actor_id, $auth_actor['account_id']]);
        $target_actor = $stmt->fetch();
        if (!$target_actor) {
            http_response_code(403);
            echo json_encode(['error' => 'Actor not in your account or inactive']);
            break;
        }

        // Prevent creating a second key if actor already has an active key
        $existing_stmt = $pdo->prepare(
            "SELECT COUNT(*) as cnt FROM api_keys WHERE actor_id = ? AND is_active = 1"
        );
        $existing_stmt->execute([$target_actor_id]);
        $existing_count = (int)$existing_stmt->fetch()['cnt'];

        if ($existing_count > 0) {
            http_response_code(409);
            echo json_encode([
                'error' => 'Actor already has an active API key. Use POST /keys/rotate to replace it.',
                'reason' => 'Multiple keys per actor would break encryption — each key derives a different keypair',
            ]);
            break;
        }

        // Generate the raw key
        $raw_key = bin2hex(random_bytes(32));
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
            echo json_encode(['error' => 'Failed to create key']);
            break;
        }

        // Build onboarding helpers with the newly generated key
        $mcp_config = [
            'roots' => [
                'type' => 'stdio',
                'command' => 'node',
                'args' => ['/path/to/roots-mcp/server.js'],
                'env' => ['ROOTS_API_KEY' => $raw_key],
            ],
        ];

        $creator_name = $auth_actor['name'];
        $creator_id = (int)$auth_actor['actor_id'];
        $prompt_snippet = "Check your Roots inbox every run:\n"
            . "curl -s -H \"X-API-Key: $raw_key\" https://roots.chatforest.com/api/v1/inbox\n\n"
            . "Messages from $creator_name (actor_id $creator_id) are your instructions. Reply:\n"
            . "curl -s -X POST -H \"X-API-Key: $raw_key\" -H \"Content-Type: application/json\" "
            . "https://roots.chatforest.com/api/v1/inbox -d '{\"recipient_actor_ids\": [$creator_id], \"body\": \"status\"}'";

        http_response_code(201);
        echo json_encode([
            'key_id' => $new_key_id,
            'actor_id' => (int)$target_actor_id,
            'api_key' => $raw_key,
            'key_prefix' => $key_prefix,
            'public_key_hex' => bin2hex($keys['public_key']),
            'warning' => 'Store this API key securely — it cannot be retrieved again',
            'mcp_config' => $mcp_config,
            'prompt_snippet' => $prompt_snippet,
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
