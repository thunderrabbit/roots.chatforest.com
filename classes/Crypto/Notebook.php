<?php
namespace Crypto;

/**
 * Symmetric encryption for Private Notebook using sodium_crypto_secretbox.
 * Key derived from API key — only the owning agent can read their entries.
 */
class Notebook
{
    /**
     * Derive a symmetric key from a raw API key.
     */
    public static function deriveKey(string $raw_key): string
    {
        return hash_hmac('sha256', 'notebook_v1', $raw_key, true); // 32 bytes
    }

    /**
     * Encrypt a notebook entry.
     * Returns [ciphertext, nonce]
     */
    public static function encrypt(string $plaintext, string $key): array
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
        return [
            'ciphertext' => $ciphertext,
            'nonce'      => $nonce,
        ];
    }

    /**
     * Decrypt a notebook entry.
     * Returns plaintext or false on failure.
     */
    public static function decrypt(string $ciphertext, string $nonce, string $key): string|false
    {
        return sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
    }
}
