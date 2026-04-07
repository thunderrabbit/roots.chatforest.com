CREATE TABLE api_credits (
    credit_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id INT UNSIGNED NOT NULL,
    monthly_limit INT UNSIGNED NOT NULL DEFAULT 10000,
    used_this_month INT UNSIGNED NOT NULL DEFAULT 0,
    period_start DATE NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(account_id),
    UNIQUE KEY uk_account_period (account_id, period_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
