CREATE TABLE actors (
    actor_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id INT UNSIGNED NOT NULL,
    name VARCHAR(100) NOT NULL,
    actor_type ENUM('agent','human','system') NOT NULL DEFAULT 'agent',
    public_key VARBINARY(32) DEFAULT NULL COMMENT 'X25519 public key for inbox encryption',
    can_read_inbox TINYINT(1) NOT NULL DEFAULT 1,
    can_write_inbox TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    FOREIGN KEY (account_id) REFERENCES accounts(account_id),
    KEY idx_account (account_id),
    KEY idx_type (actor_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
