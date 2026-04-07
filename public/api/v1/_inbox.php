<?php
/**
 * Encrypted Inbox endpoints
 *
 * GET    /inbox                    — list messages for caller (decrypted)
 * GET    /inbox/{message_id}       — get single message (decrypted)
 * POST   /inbox                    — send message (encrypted per-recipient)
 * PATCH  /inbox/{recipient_id}     — update status (read/archived/deleted)
 */

$method = $_SERVER['REQUEST_METHOD'];
$id_param = isset($segments[3]) ? (int)$segments[3] : null;

// Derive caller's secret key for decryption
$caller_keys = \Crypto\Inbox::deriveKeypair($raw_key);
$caller_secret = $caller_keys['secret_key'];
$caller_public = $caller_keys['public_key'];

switch ($method) {
    case 'GET':
        if ($id_param) {
            // GET /inbox/{message_id} — single message
            $stmt = $pdo->prepare(
                "SELECT mr.recipient_id, mr.message_id, m.sender_actor_id, a.name as sender_name,
                        m.subject, mr.ciphertext, mr.nonce, mr.status, mr.read_at, m.created_at,
                        sa.public_key as sender_public_key
                 FROM message_recipients mr
                 JOIN messages m ON m.message_id = mr.message_id
                 JOIN actors a ON a.actor_id = m.sender_actor_id
                 JOIN actors sa ON sa.actor_id = m.sender_actor_id
                 WHERE mr.message_id = ? AND mr.recipient_actor_id = ?"
            );
            $stmt->execute([$id_param, $auth_actor['actor_id']]);
            $row = $stmt->fetch();
            if (!$row) {
                http_response_code(404);
                echo json_encode(['error' => 'Message not found']);
                break;
            }

            $plaintext = \Crypto\Inbox::decrypt(
                $row['ciphertext'], $row['nonce'],
                $row['sender_public_key'], $caller_secret
            );

            echo json_encode([
                'recipient_id' => (int)$row['recipient_id'],
                'message_id' => (int)$row['message_id'],
                'sender_actor_id' => (int)$row['sender_actor_id'],
                'sender_name' => $row['sender_name'],
                'subject' => $row['subject'],
                'body' => $plaintext !== false ? $plaintext : '[DECRYPTION FAILED]',
                'status' => $row['status'],
                'read_at' => $row['read_at'],
                'created_at' => $row['created_at'],
            ]);
        } else {
            // GET /inbox — list messages
            $status_filter = $_GET['status'] ?? 'unread';
            $limit = min((int)($_GET['limit'] ?? 50), 100);
            $offset = max((int)($_GET['offset'] ?? 0), 0);

            $valid_statuses = ['unread', 'read', 'archived', 'all'];
            if (!in_array($status_filter, $valid_statuses)) {
                $status_filter = 'unread';
            }

            $where = "mr.recipient_actor_id = ?";
            $params = [$auth_actor['actor_id']];
            if ($status_filter !== 'all') {
                $where .= " AND mr.status = ?";
                $params[] = $status_filter;
            } else {
                $where .= " AND mr.status != 'deleted'";
            }
            $params[] = $limit;
            $params[] = $offset;

            $stmt = $pdo->prepare(
                "SELECT mr.recipient_id, mr.message_id, m.sender_actor_id, a.name as sender_name,
                        m.subject, mr.ciphertext, mr.nonce, mr.status, mr.read_at, m.created_at,
                        sa.public_key as sender_public_key
                 FROM message_recipients mr
                 JOIN messages m ON m.message_id = mr.message_id
                 JOIN actors a ON a.actor_id = m.sender_actor_id
                 JOIN actors sa ON sa.actor_id = m.sender_actor_id
                 WHERE $where
                 ORDER BY m.created_at DESC
                 LIMIT ? OFFSET ?"
            );
            $stmt->execute($params);
            $rows = $stmt->fetchAll();

            $messages = [];
            foreach ($rows as $row) {
                $plaintext = \Crypto\Inbox::decrypt(
                    $row['ciphertext'], $row['nonce'],
                    $row['sender_public_key'], $caller_secret
                );
                $messages[] = [
                    'recipient_id' => (int)$row['recipient_id'],
                    'message_id' => (int)$row['message_id'],
                    'sender_actor_id' => (int)$row['sender_actor_id'],
                    'sender_name' => $row['sender_name'],
                    'subject' => $row['subject'],
                    'body' => $plaintext !== false ? $plaintext : '[DECRYPTION FAILED]',
                    'status' => $row['status'],
                    'created_at' => $row['created_at'],
                ];
            }

            // Count total
            $count_stmt = $pdo->prepare(
                "SELECT COUNT(*) FROM message_recipients mr
                 JOIN messages m ON m.message_id = mr.message_id
                 WHERE " . str_replace([" LIMIT ? OFFSET ?"], [''], $where)
            );
            // Re-run with just the where params (no limit/offset)
            $count_params = array_slice($params, 0, -2);
            $count_stmt = $pdo->prepare(
                "SELECT COUNT(*) as total FROM message_recipients mr WHERE mr.recipient_actor_id = ?" .
                ($status_filter !== 'all' ? " AND mr.status = ?" : " AND mr.status != 'deleted'")
            );
            $count_stmt->execute($count_params);
            $total = (int)$count_stmt->fetch()['total'];

            echo json_encode([
                'messages' => $messages,
                'total' => $total,
                'limit' => $limit,
                'offset' => $offset,
            ]);
        }
        break;

    case 'POST':
        // Send a message — encrypt per-recipient
        if (!$auth_actor['can_write_inbox']) {
            http_response_code(403);
            echo json_encode(['error' => 'Actor does not have inbox write permission']);
            break;
        }

        $input = json_decode(file_get_contents('php://input'), true);
        $body = $input['body'] ?? '';
        $subject = $input['subject'] ?? null;
        $recipient_ids = $input['recipient_actor_ids'] ?? [];

        if (empty($body)) {
            http_response_code(400);
            echo json_encode(['error' => 'body is required']);
            break;
        }
        if (empty($recipient_ids) || !is_array($recipient_ids)) {
            http_response_code(400);
            echo json_encode(['error' => 'recipient_actor_ids array is required']);
            break;
        }

        // Fetch recipients' public keys
        $placeholders = implode(',', array_fill(0, count($recipient_ids), '?'));
        $stmt = $pdo->prepare(
            "SELECT actor_id, public_key, name FROM actors
             WHERE actor_id IN ($placeholders) AND is_active = 1 AND can_read_inbox = 1"
        );
        $stmt->execute($recipient_ids);
        $recipients = $stmt->fetchAll();

        if (empty($recipients)) {
            http_response_code(400);
            echo json_encode(['error' => 'No valid recipients found']);
            break;
        }

        $missing_keys = array_filter($recipients, fn($r) => empty($r['public_key']));
        if (!empty($missing_keys)) {
            $names = array_map(fn($r) => $r['name'], $missing_keys);
            http_response_code(400);
            echo json_encode(['error' => 'Recipients missing public keys: ' . implode(', ', $names)]);
            break;
        }

        $pdo->beginTransaction();
        try {
            // Create message record
            $stmt = $pdo->prepare(
                "INSERT INTO messages (sender_actor_id, subject) VALUES (?, ?)"
            );
            $stmt->execute([$auth_actor['actor_id'], $subject]);
            $message_id = (int)$pdo->lastInsertId();

            // Encrypt and store one copy per recipient
            $insert_stmt = $pdo->prepare(
                "INSERT INTO message_recipients (message_id, recipient_actor_id, ciphertext, nonce)
                 VALUES (?, ?, ?, ?)"
            );

            $delivered_to = [];
            foreach ($recipients as $recipient) {
                $encrypted = \Crypto\Inbox::encrypt(
                    $body,
                    $recipient['public_key'],
                    $caller_secret
                );
                $insert_stmt->execute([
                    $message_id,
                    $recipient['actor_id'],
                    $encrypted['ciphertext'],
                    $encrypted['nonce'],
                ]);
                $delivered_to[] = [
                    'actor_id' => (int)$recipient['actor_id'],
                    'name' => $recipient['name'],
                ];
            }

            $pdo->commit();

            http_response_code(201);
            echo json_encode([
                'message_id' => $message_id,
                'delivered_to' => $delivered_to,
                'subject' => $subject,
            ]);
        } catch (\Exception $e) {
            $pdo->rollBack();
            http_response_code(500);
            echo json_encode(['error' => 'Failed to send message: ' . $e->getMessage()]);
        }
        break;

    case 'PATCH':
        // Update message status
        if (!$id_param) {
            http_response_code(400);
            echo json_encode(['error' => 'recipient_id required']);
            break;
        }

        $input = json_decode(file_get_contents('php://input'), true);
        $new_status = $input['status'] ?? null;
        if (!in_array($new_status, ['read', 'archived', 'deleted'])) {
            http_response_code(400);
            echo json_encode(['error' => 'status must be read, archived, or deleted']);
            break;
        }

        $read_at = $new_status === 'read' ? "NOW()" : "read_at";
        $stmt = $pdo->prepare(
            "UPDATE message_recipients SET status = ?, read_at = IF(? = 'read' AND read_at IS NULL, NOW(), read_at)
             WHERE recipient_id = ? AND recipient_actor_id = ?"
        );
        $stmt->execute([$new_status, $new_status, $id_param, $auth_actor['actor_id']]);

        if ($stmt->rowCount() === 0) {
            http_response_code(404);
            echo json_encode(['error' => 'Message not found']);
            break;
        }

        echo json_encode(['status' => 'updated', 'recipient_id' => $id_param, 'new_status' => $new_status]);
        break;

    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
}
