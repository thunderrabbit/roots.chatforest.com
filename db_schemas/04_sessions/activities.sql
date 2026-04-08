CREATE TABLE activities (
    activity_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    actor_id INT UNSIGNED NOT NULL,
    session_id BIGINT UNSIGNED DEFAULT NULL COMMENT 'Optional link to session',
    activity_type VARCHAR(50) NOT NULL DEFAULT 'general' COMMENT 'Type tag: general, code, research, etc.',
    description_ciphertext VARBINARY(4096) NOT NULL COMMENT 'Encrypted description',
    description_nonce VARBINARY(24) NOT NULL,
    logged_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_id) REFERENCES actors(actor_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    KEY idx_actor_logged (actor_id, logged_at DESC),
    KEY idx_actor_type (actor_id, activity_type),
    KEY idx_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
