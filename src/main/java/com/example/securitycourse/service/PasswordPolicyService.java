package com.example.securitycourse.service;

import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.regex.Pattern;

@Service
public class PasswordPolicyService {

    private static final int MIN_LEN = 8;

    private static final Pattern HAS_UPPER = Pattern.compile(".*[A-Z].*");
    private static final Pattern HAS_DIGIT = Pattern.compile(".*\\d.*");
    private static final Pattern HAS_SPECIAL = Pattern.compile(".*[^A-Za-z0-9].*");

    private static final Set<String> BLACKLIST = Set.of(
            "password",
            "password123",
            "12345678",
            "qwerty123",
            "admin123",
            "letmein"
    );

    public void validateOrThrow(String rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("Password is required");
        }
        String p = rawPassword.trim();
        if (p.length() < MIN_LEN) {
            throw new IllegalArgumentException("Password must be at least " + MIN_LEN + " characters");
        }
        if (!HAS_UPPER.matcher(p).matches()) {
            throw new IllegalArgumentException("Password must contain at least one uppercase letter");
        }
        if (!HAS_DIGIT.matcher(p).matches()) {
            throw new IllegalArgumentException("Password must contain at least one digit");
        }
        if (!HAS_SPECIAL.matcher(p).matches()) {
            throw new IllegalArgumentException("Password must contain at least one special character");
        }
        if (BLACKLIST.contains(p.toLowerCase())) {
            throw new IllegalArgumentException("Password is too common");
        }
    }
}
