CREATE TABLE message_recipients (
    recipient_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    message_id BIGINT UNSIGNED NOT NULL,
    recipient_actor_id INT UNSIGNED NOT NULL,
    ciphertext MEDIUMBLOB NOT NULL COMMENT 'sodium_crypto_box encrypted message body',
    nonce VARBINARY(24) NOT NULL COMMENT 'crypto_box nonce',
    status ENUM('unread','read','archived','deleted','seen','in_progress','cancelled','blocked','needs_human') NOT NULL DEFAULT 'unread',
    read_at DATETIME DEFAULT NULL,
    FOREIGN KEY (message_id) REFERENCES messages(message_id),
    FOREIGN KEY (recipient_actor_id) REFERENCES actors(actor_id),
    KEY idx_recipient_status (recipient_actor_id, status),
    KEY idx_message (message_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
