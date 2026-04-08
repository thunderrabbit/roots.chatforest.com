CREATE TABLE todo_logs (
    log_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    todo_id BIGINT UNSIGNED NOT NULL,
    actor_id INT UNSIGNED NOT NULL,
    old_status ENUM('open','in_progress','done','cancelled') DEFAULT NULL,
    new_status ENUM('open','in_progress','done','cancelled') NOT NULL,
    note_ciphertext VARBINARY(2048) DEFAULT NULL COMMENT 'Encrypted transition note',
    note_nonce VARBINARY(24) DEFAULT NULL,
    logged_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (todo_id) REFERENCES todos(todo_id),
    FOREIGN KEY (actor_id) REFERENCES actors(actor_id),
    KEY idx_todo (todo_id, logged_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
