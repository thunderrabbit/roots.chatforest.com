CREATE TABLE sessions (
    session_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    actor_id INT UNSIGNED NOT NULL,
    status ENUM('active','ended') NOT NULL DEFAULT 'active',
    notes_ciphertext VARBINARY(4096) DEFAULT NULL COMMENT 'Encrypted session notes',
    notes_nonce VARBINARY(24) DEFAULT NULL,
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_id) REFERENCES actors(actor_id),
    KEY idx_actor_status (actor_id, status),
    KEY idx_actor_started (actor_id, started_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
