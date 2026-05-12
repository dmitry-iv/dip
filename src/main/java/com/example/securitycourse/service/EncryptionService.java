package com.example.securitycourse.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Симметричное шифрование AES-GCM-256 для хранения секретов в БД
 * (например, паролей SMTP). Мастер-ключ берётся из переменной окружения
 * APP_ENCRYPTION_KEY и НИКОГДА не хранится в БД.
 *
 * Закрывает требование OWASP A02 (Cryptographic Failures) для секретов в покое.
 *
 * Формат хранения: "v1:" + Base64(IV(12) || ciphertext || tag(16))
 * Префикс "v1:" нужен чтобы различать зашифрованные значения и старые plaintext
 * (для бесшовной миграции существующих БД).
 */
@Service
public class EncryptionService {

    private static final Logger log = LoggerFactory.getLogger(EncryptionService.class);

    private static final String PREFIX = "v1:";
    private static final String CIPHER_ALGO = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;     // bytes
    private static final int GCM_TAG_LENGTH = 128;   // bits

    private final SecureRandom secureRandom = new SecureRandom();
    private SecretKey masterKey;

    @Value("${app.security.encryption.key:DEV-ONLY-INSECURE-KEY-CHANGE-IN-PRODUCTION-32+chars-please}")
    private String configuredKey;

    @PostConstruct
    public void init() {
        try {
            // SHA-256 от настроенной строки → ровно 32 байта для AES-256.
            // Это позволяет задавать ключ человекочитаемой строкой произвольной длины.
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = md.digest(configuredKey.getBytes(StandardCharsets.UTF_8));
            this.masterKey = new SecretKeySpec(keyBytes, "AES");
            if (configuredKey.startsWith("DEV-ONLY-")) {
                log.warn("EncryptionService: using DEV default key. " +
                        "Set environment variable APP_ENCRYPTION_KEY for production.");
            } else {
                log.info("EncryptionService initialized (key length: {} chars).", configuredKey.length());
            }
        } catch (Exception e) {
            throw new IllegalStateException("Cannot initialize EncryptionService", e);
        }
    }

    /** Шифрует строку. null или пустую возвращает как есть. */
    public String encrypt(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) return plaintext;
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ct, 0, combined, iv.length, ct.length);

            return PREFIX + Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    /**
     * Расшифровывает строку. Если строка БЕЗ префикса "v1:" — возвращает как есть
     * (это plaintext-значение от старых версий, до включения шифрования).
     */
    public String decrypt(String value) {
        if (value == null || value.isEmpty()) return value;
        if (!value.startsWith(PREFIX)) {
            return value;
        }
        try {
            byte[] combined = Base64.getDecoder().decode(value.substring(PREFIX.length()));
            if (combined.length < GCM_IV_LENGTH + 16) {
                throw new IllegalStateException("Encrypted value too short");
            }
            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
            byte[] ct = new byte[combined.length - GCM_IV_LENGTH];
            System.arraycopy(combined, GCM_IV_LENGTH, ct, 0, ct.length);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            byte[] pt = cipher.doFinal(ct);

            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Decryption failed (wrong key or corrupted data?)", e);
        }
    }

    public boolean isEncrypted(String value) {
        return value != null && value.startsWith(PREFIX);
    }
}