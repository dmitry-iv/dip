package com.example.securitycourse.service;

import com.example.securitycourse.service.EncryptionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты симметричного шифрования AES-GCM-256.
 * Проверяют: round-trip, обработку null/пустых значений, обратную совместимость с plaintext,
 * детекцию подделки (GCM authentication tag), уникальность IV при каждом шифровании.
 */
@DisplayName("EncryptionService — AES-GCM-256")
class EncryptionServiceTest {

    private EncryptionService service;

    @BeforeEach
    void setUp() {
        service = new EncryptionService();
        // Подставляем тестовый ключ через рефлексию (нет Spring-контекста в unit-тесте)
        ReflectionTestUtils.setField(service, "configuredKey",
                "TEST-MASTER-KEY-FOR-UNIT-TESTS-DO-NOT-USE-IN-PROD");
        service.init();
    }

    @Test
    @DisplayName("Шифрование и расшифровка возвращают исходное значение")
    void encryptDecrypt_roundTrip() {
        String plaintext = "MySecretPassword123!";

        String encrypted = service.encrypt(plaintext);
        String decrypted = service.decrypt(encrypted);

        assertEquals(plaintext, decrypted);
    }

    @Test
    @DisplayName("Шифрованное значение имеет префикс v1: и отличается от plaintext")
    void encrypt_hasVersionPrefix() {
        String encrypted = service.encrypt("secret");

        assertTrue(encrypted.startsWith("v1:"),
                "Encrypted value must start with 'v1:' for migration compatibility");
        assertNotEquals("secret", encrypted);
    }

    @Test
    @DisplayName("Шифрование одной и той же строки дважды даёт РАЗНЫЕ результаты (IV случайный)")
    void encrypt_producesDifferentCiphertextsEachTime() {
        String plaintext = "same-plaintext";

        String enc1 = service.encrypt(plaintext);
        String enc2 = service.encrypt(plaintext);

        assertNotEquals(enc1, enc2,
                "AES-GCM with random IV must produce different ciphertexts for same plaintext " +
                        "(otherwise vulnerable to known-plaintext attacks)");

        // Но расшифровка обоих даёт одинаковый plaintext
        assertEquals(service.decrypt(enc1), service.decrypt(enc2));
    }

    @Test
    @DisplayName("null и пустая строка возвращаются как есть (для облегчения миграций)")
    void encrypt_handlesNullAndEmpty() {
        assertNull(service.encrypt(null));
        assertEquals("", service.encrypt(""));
        assertNull(service.decrypt(null));
        assertEquals("", service.decrypt(""));
    }

    @Test
    @DisplayName("Plaintext без префикса v1: возвращается как есть (backward compatibility)")
    void decrypt_returnsPlaintextAsIs_whenNoPrefix() {
        String oldPlaintext = "legacy-password-without-encryption";

        String result = service.decrypt(oldPlaintext);

        assertEquals(oldPlaintext, result,
                "Decryption must pass-through plaintext values for migration from " +
                        "pre-encryption versions of the schema");
    }

    @Test
    @DisplayName("Модификация шифротекста обнаруживается через GCM authentication tag")
    void decrypt_detectsTamperingViaGcmTag() {
        String encrypted = service.encrypt("important-data");

        // Подменяем один символ в середине Base64-части (после "v1:")
        char[] chars = encrypted.toCharArray();
        int mid = chars.length / 2;
        chars[mid] = (chars[mid] == 'A') ? 'B' : 'A';
        String tampered = new String(chars);

        assertThrows(IllegalStateException.class,
                () -> service.decrypt(tampered),
                "GCM authentication tag must detect any modification of ciphertext");
    }

    @Test
    @DisplayName("Расшифровка с другим ключом проваливается")
    void decrypt_failsWithWrongKey() {
        String encrypted = service.encrypt("secret");

        // Создаём вторую инстанцию с другим ключом
        EncryptionService other = new EncryptionService();
        ReflectionTestUtils.setField(other, "configuredKey", "COMPLETELY-DIFFERENT-KEY-XYZ");
        other.init();

        assertThrows(IllegalStateException.class,
                () -> other.decrypt(encrypted),
                "Decryption with wrong key must throw, not silently return garbage");
    }

    @Test
    @DisplayName("isEncrypted корректно определяет шифрованные и нешифрованные значения")
    void isEncrypted_detection() {
        assertTrue(service.isEncrypted("v1:abcdef123456"));
        assertFalse(service.isEncrypted("plaintext-value"));
        assertFalse(service.isEncrypted(""));
        assertFalse(service.isEncrypted(null));
    }
}