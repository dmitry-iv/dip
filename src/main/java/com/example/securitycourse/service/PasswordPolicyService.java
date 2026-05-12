package com.example.securitycourse.service;

import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.regex.Pattern;

@Service
public class PasswordPolicyService {

    private static final int MIN_LEN = 12;

    private static final Pattern HAS_UPPER   = Pattern.compile(".*[A-Z].*");
    private static final Pattern HAS_LOWER   = Pattern.compile(".*[a-z].*");
    private static final Pattern HAS_DIGIT   = Pattern.compile(".*\\d.*");
    private static final Pattern HAS_SPECIAL = Pattern.compile(".*[^A-Za-z0-9].*");

    /** Расширенный blacklist распространённых паролей (NIST SP 800-63B). */
    private static final Set<String> BLACKLIST = Set.of(
            "password", "password123", "12345678", "123456789", "1234567890",
            "qwerty", "qwerty123", "qwertyuiop", "admin", "admin123",
            "letmein", "welcome", "welcome123", "iloveyou", "monkey",
            "dragon", "master", "abc12345", "p@ssw0rd", "passw0rd",
            "administrator", "supervisor", "operator", "корпорация",
            "корпоратив", "пароль123"
    );

    public void validateOrThrow(String rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("Password is required");
        }
        String p = rawPassword.trim();
        if (p.length() < MIN_LEN) {
            throw new IllegalArgumentException("Пароль должен содержать минимум " + MIN_LEN + " символов");
        }
        if (!HAS_UPPER.matcher(p).matches()) {
            throw new IllegalArgumentException("Пароль должен содержать хотя бы одну заглавную букву");
        }
        if (!HAS_LOWER.matcher(p).matches()) {
            throw new IllegalArgumentException("Пароль должен содержать хотя бы одну строчную букву");
        }
        if (!HAS_DIGIT.matcher(p).matches()) {
            throw new IllegalArgumentException("Пароль должен содержать хотя бы одну цифру");
        }
        if (!HAS_SPECIAL.matcher(p).matches()) {
            throw new IllegalArgumentException("Пароль должен содержать хотя бы один спецсимвол");
        }
        if (BLACKLIST.contains(p.toLowerCase())) {
            throw new IllegalArgumentException("Пароль входит в список распространённых");
        }
        if (hasSequential(p)) {
            throw new IllegalArgumentException("Пароль содержит длинную последовательность символов");
        }
    }

    private boolean hasSequential(String p) {
        int run = 1;
        for (int i = 1; i < p.length(); i++) {
            if (p.charAt(i) == p.charAt(i - 1) + 1) {
                run++;
                if (run >= 5) return true;
            } else {
                run = 1;
            }
        }
        return false;
    }
}