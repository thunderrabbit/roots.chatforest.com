CREATE TABLE todos (
    todo_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    actor_id INT UNSIGNED NOT NULL,
    session_id BIGINT UNSIGNED DEFAULT NULL COMMENT 'Optional link to session',
    title_ciphertext VARBINARY(1024) NOT NULL COMMENT 'Encrypted title',
    title_nonce VARBINARY(24) NOT NULL,
    description_ciphertext VARBINARY(4096) DEFAULT NULL COMMENT 'Encrypted description',
    description_nonce VARBINARY(24) DEFAULT NULL,
    status ENUM('open','in_progress','done','cancelled') NOT NULL DEFAULT 'open',
    priority TINYINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '0=normal, 1=low, 2=medium, 3=high',
    due_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_id) REFERENCES actors(actor_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    KEY idx_actor_status (actor_id, status),
    KEY idx_actor_due (actor_id, due_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
