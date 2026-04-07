CREATE TABLE actor_visibility (
    watcher_actor_id INT UNSIGNED NOT NULL,
    watched_actor_id INT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (watcher_actor_id, watched_actor_id),
    FOREIGN KEY (watcher_actor_id) REFERENCES actors(actor_id),
    FOREIGN KEY (watched_actor_id) REFERENCES actors(actor_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
