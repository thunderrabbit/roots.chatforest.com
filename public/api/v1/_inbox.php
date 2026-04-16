<?php
/**
 * Encrypted Inbox endpoints
 *
 * GET    /inbox                    — list messages for caller (decrypted)
 * GET    /inbox/{message_id}       — get single message (decrypted)
 * POST   /inbox                    — send message (encrypted per-recipient)
 * PATCH  /inbox/{recipient_id}     — update status (read/archived/deleted/seen/in_progress/cancelled/blocked/needs_human)
 */

$method = $_SERVER['REQUEST_METHOD'];
$id_param = isset($segments[3]) ? (int)$segments[3] : null;

// Derive caller's secret key for decryption
$caller_keys = \Crypto\Inbox::deriveKeypair($raw_key);
$caller_secret = $caller_keys['secret_key'];
$caller_public = $caller_keys['public_key'];

/**
 * Decrypt subject from per-recipient encrypted copy, falling back to
 * plaintext messages.subject for pre-migration messages.
 */
function decryptSubject($row, $caller_secret) {
    if (!empty($row['subject_ciphertext']) && !empty($row['subject_nonce'])) {
        $plain = \Crypto\Inbox::decrypt(
            $row['subject_ciphertext'], $row['subject_nonce'],
            $row['sender_public_key'], $caller_secret
        );
        return $plain !== false ? $plain : '[SUBJECT DECRYPTION FAILED]';
    }
    // Fallback for pre-migration messages with plaintext subject
    return $row['subject'] ?? '';
}

switch ($method) {
    case 'GET':
        if ($id_param) {
            // GET /inbox/{message_id} — single message
            $stmt = $pdo->prepare(
                "SELECT mr.recipient_id, mr.message_id, m.sender_actor_id, a.name as sender_name,
                        m.subject, mr.subject_ciphertext, mr.subject_nonce,
                        mr.ciphertext, mr.nonce, mr.status, mr.read_at, m.created_at,
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
                'subject' => decryptSubject($row, $caller_secret),
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

            $valid_statuses = ['unread', 'read', 'archived', 'seen', 'in_progress', 'cancelled', 'blocked', 'needs_human', 'all'];
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

            // Count total (before adding limit/offset to params)
            $count_stmt = $pdo->prepare(
                "SELECT COUNT(*) as total FROM message_recipients mr WHERE $where"
            );
            $count_stmt->execute($params);
            $total = (int)$count_stmt->fetch()['total'];

            $params[] = $limit;
            $params[] = $offset;

            $stmt = $pdo->prepare(
                "SELECT mr.recipient_id, mr.message_id, m.sender_actor_id, a.name as sender_name,
                        m.subject, mr.subject_ciphertext, mr.subject_nonce,
                        mr.ciphertext, mr.nonce, mr.status, mr.read_at, m.created_at,
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
                    'subject' => decryptSubject($row, $caller_secret),
                    'body' => $plaintext !== false ? $plaintext : '[DECRYPTION FAILED]',
                    'status' => $row['status'],
                    'created_at' => $row['created_at'],
                ];
            }

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

        // Fetch recipients' public keys (same account only)
        $placeholders = implode(',', array_fill(0, count($recipient_ids), '?'));
        $stmt = $pdo->prepare(
            "SELECT actor_id, public_key, name FROM actors
             WHERE actor_id IN ($placeholders) AND is_active = 1 AND can_read_inbox = 1
             AND account_id = ?"
        );
        $params = $recipient_ids;
        $params[] = $auth_actor['account_id'];
        $stmt->execute($params);
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
            // Create message record — subject stored as NULL (encrypted per-recipient)
            $stmt = $pdo->prepare(
                "INSERT INTO messages (sender_actor_id, subject) VALUES (?, ?)"
            );
            $stmt->execute([$auth_actor['actor_id'], null]);
            $message_id = (int)$pdo->lastInsertId();

            // Encrypt and store one copy per recipient (body + subject)
            $insert_stmt = $pdo->prepare(
                "INSERT INTO message_recipients
                    (message_id, recipient_actor_id, ciphertext, nonce, subject_ciphertext, subject_nonce)
                 VALUES (?, ?, ?, ?, ?, ?)"
            );

            $delivered_to = [];
            foreach ($recipients as $recipient) {
                // Encrypt body
                $encrypted_body = \Crypto\Inbox::encrypt(
                    $body,
                    $recipient['public_key'],
                    $caller_secret
                );
                // Encrypt subject (if provided)
                $enc_subject = null;
                $enc_subject_nonce = null;
                if ($subject !== null) {
                    $encrypted_subj = \Crypto\Inbox::encrypt(
                        $subject,
                        $recipient['public_key'],
                        $caller_secret
                    );
                    $enc_subject = $encrypted_subj['ciphertext'];
                    $enc_subject_nonce = $encrypted_subj['nonce'];
                }
                $insert_stmt->execute([
                    $message_id,
                    $recipient['actor_id'],
                    $encrypted_body['ciphertext'],
                    $encrypted_body['nonce'],
                    $enc_subject,
                    $enc_subject_nonce,
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
                'encrypted_fields' => ['body', 'subject'],
            ]);
        } catch (\Exception $e) {
            $pdo->rollBack();
            http_response_code(500);
            echo json_encode(['error' => 'Failed to send message']);
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
        if (!in_array($new_status, ['read', 'archived', 'deleted', 'seen', 'in_progress', 'cancelled', 'blocked', 'needs_human'])) {
            http_response_code(400);
            echo json_encode(['error' => 'status must be one of: read, archived, deleted, seen, in_progress, cancelled, blocked, needs_human']);
            break;
        }

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
