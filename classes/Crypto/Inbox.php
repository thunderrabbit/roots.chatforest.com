<?php
namespace Crypto;

/**
 * Public-key encryption for inbox messages using sodium_crypto_box.
 * Keypairs are deterministically derived from API keys — private keys are NEVER stored.
 */
class Inbox
{
    /**
     * Derive a keypair from a raw API key.
     * Returns [public_key, secret_key, keypair]
     */
    public static function deriveKeypair(string $raw_key): array
    {
        $seed = hash('sha256', 'inbox_v1' . $raw_key, true); // 32 bytes
        $keypair = sodium_crypto_box_seed_keypair($seed);
        return [
            'public_key'  => sodium_crypto_box_publickey($keypair),
            'secret_key'  => sodium_crypto_box_secretkey($keypair),
            'keypair'     => $keypair,
        ];
    }

    /**
     * Encrypt a message for a recipient.
     * Returns [ciphertext, nonce]
     */
    public static function encrypt(
        string $plaintext,
        string $recipient_public_key,
        string $sender_secret_key
    ): array {
        $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $sender_secret_key,
            $recipient_public_key
        );
        $ciphertext = sodium_crypto_box($plaintext, $nonce, $keypair);
        return [
            'ciphertext' => $ciphertext,
            'nonce'      => $nonce,
        ];
    }

    /**
     * Decrypt a message from a sender.
     * Returns plaintext or false on failure.
     */
    public static function decrypt(
        string $ciphertext,
        string $nonce,
        string $sender_public_key,
        string $recipient_secret_key
    ): string|false {
        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $recipient_secret_key,
            $sender_public_key
        );
        return sodium_crypto_box_open($ciphertext, $nonce, $keypair);
    }
}
