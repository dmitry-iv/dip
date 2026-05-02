package com.example.securitycourse.service;

import com.example.securitycourse.domain.AppUser;
import org.jboss.aerogear.security.otp.Totp;
import org.jboss.aerogear.security.otp.api.Base32;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
public class TotpService {

    private static final int SECRET_BYTES = 20;
    private static final int BACKUP_CODES_COUNT = 5;
    private static final int BACKUP_CODE_LENGTH = 10;

    /**
     * Генерирует base32-секрет.
     */
    public String generateSecret() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[SECRET_BYTES];
        random.nextBytes(bytes);
        return Base32.encode(bytes);
    }

    /**
     * Проверяет TOTP-код.
     */
    public boolean verifyCode(String secret, String code) {
        if (secret == null || code == null) return false;
        try {
            Totp totp = new Totp(secret);
            return totp.verify(code);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Генерирует URL для QR-кода.
     */
    public String generateQrUrl(String label, String secret, String issuer) {
        return String.format("otpauth://totp/%s?secret=%s&issuer=%s", label, secret, issuer);
    }

    /**
     * Создаёт список резервных кодов.
     */
    public List<String> generateBackupCodes() {
        SecureRandom random = new SecureRandom();
        return IntStream.range(0, BACKUP_CODES_COUNT)
                .mapToObj(i -> {
                    StringBuilder sb = new StringBuilder(BACKUP_CODE_LENGTH);
                    for (int j = 0; j < BACKUP_CODE_LENGTH; j++) {
                        sb.append((char) ('0' + random.nextInt(10)));
                    }
                    return sb.toString();
                })
                .collect(Collectors.toList());
    }

    /**
     * Проверяет и удаляет использованный резервный код.
     * Возвращает true, если код был найден и удалён.
     */
    public boolean useBackupCode(AppUser user, String code) {
        if (code == null || code.isBlank()) return false;
        List<String> codes = new ArrayList<>(user.getBackupCodesList());
        if (codes.contains(code)) {
            codes.remove(code);
            user.setBackupCodesList(codes);
            return true;
        }
        return false;
    }
}