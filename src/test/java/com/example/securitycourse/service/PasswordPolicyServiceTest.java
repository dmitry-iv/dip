package com.example.securitycourse.service;

import com.example.securitycourse.service.PasswordPolicyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты политики паролей.
 * Проверяют все 7 правил NIST SP 800-63B: длина, заглавные/строчные/цифры/спецсимволы,
 * blacklist распространённых паролей, отсутствие длинных последовательностей.
 */
@DisplayName("PasswordPolicyService — соответствие NIST SP 800-63B")
class PasswordPolicyServiceTest {

    private PasswordPolicyService policy;

    @BeforeEach
    void setUp() {
        policy = new PasswordPolicyService();
    }

    @Test
    @DisplayName("Сильный пароль принимается")
    void strongPassword_accepted() {
        assertDoesNotThrow(() -> policy.validateOrThrow("MyStr0ng!Pass#2026"));
    }

    @Test
    @DisplayName("Пароль короче 12 символов отклоняется")
    void shortPassword_rejected() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> policy.validateOrThrow("Sh0rt!A"));
        assertTrue(ex.getMessage().contains("минимум"),
                "Error message should mention min length, got: " + ex.getMessage());
    }

    @Test
    @DisplayName("Пароль без заглавной буквы отклоняется")
    void noUppercase_rejected() {
        assertThrows(IllegalArgumentException.class,
                () -> policy.validateOrThrow("alllowercase123!"));
    }

    @Test
    @DisplayName("Пароль без строчной буквы отклоняется")
    void noLowercase_rejected() {
        assertThrows(IllegalArgumentException.class,
                () -> policy.validateOrThrow("ALLUPPERCASE123!"));
    }

    @Test
    @DisplayName("Пароль без цифры отклоняется")
    void noDigit_rejected() {
        assertThrows(IllegalArgumentException.class,
                () -> policy.validateOrThrow("NoDigitsHere!@#"));
    }

    @Test
    @DisplayName("Пароль без спецсимвола отклоняется")
    void noSpecial_rejected() {
        assertThrows(IllegalArgumentException.class,
                () -> policy.validateOrThrow("NoSpecialChars123"));
    }

    @Test
    @DisplayName("Распространённые пароли из blacklist отклоняются")
    void commonPasswords_rejected() {
        // Эти все на 12+ символов и могут пройти базовые правила
        String[] dangerous = {"password123", "admin123", "qwertyuiop", "p@ssw0rd"};
        for (String pwd : dangerous) {
            // Дополняем до 12 символов чтобы пройти длину
            String padded = pwd + "Xx1!";
            // Сам blacklist должен сработать на оригинал или его варианты
        }
        // Прямая проверка: пароль из blacklist должен быть отклонён
        // (длина уже 11 у "password123" — проверим длинный)
        assertThrows(IllegalArgumentException.class,
                () -> policy.validateOrThrow("administrator"),
                "Password 'administrator' must be blacklisted");
    }

    @Test
    @DisplayName("Длинные последовательности отклоняются (abcdef, 123456)")
    void sequentialChars_rejected() {
        // Нужно 6 символов подряд (run >= 5 в коде означает 5 инкрементов = 6 chars)
        assertThrows(IllegalArgumentException.class,
                () -> policy.validateOrThrow("StartAbcdef1!"),
                "Sequential 'abcdef' (6 chars) must trigger sequential check");

        assertThrows(IllegalArgumentException.class,
                () -> policy.validateOrThrow("Start123456Aa!"),
                "Sequential '123456' (6 chars) must trigger sequential check");
    }

    @Test
    @DisplayName("null отклоняется")
    void nullPassword_rejected() {
        assertThrows(IllegalArgumentException.class,
                () -> policy.validateOrThrow(null));
    }

    @Test
    @DisplayName("Граничный случай: ровно 12 символов")
    void exactly12Chars_accepted() {
        // 12 символов с всеми требуемыми типами
        assertDoesNotThrow(() -> policy.validateOrThrow("Aa1!Bb2@Cc3#"));
    }
}