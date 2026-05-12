package com.example.securitycourse.service;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditResults;
import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.repository.UserRepository;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Двухфакторная аутентификация (TOTP RFC 6238).
 * Поддерживает Google Authenticator, Microsoft Authenticator, Authy, FreeOTP и т.п.
 *
 * Закрывает требование OWASP A07 (Identification and Authentication Failures).
 */
@Service
public class TwoFactorService {

    private static final int BACKUP_CODES_COUNT = 10;
    private static final String BACKUP_CODE_CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static final int BACKUP_CODE_LENGTH = 10;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder; // для хеширования backup-кодов
    private final AuditService auditService;

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final QrGenerator qrGenerator = new ZxingPngQrGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1);
    private final CodeVerifier codeVerifier;

    private final SecureRandom random = new SecureRandom();

    @Value("${app.security.totp.issuer:CorpSec}")
    private String issuer;

    @Value("${app.security.totp.window:1}")
    private int allowedWindow;

    public TwoFactorService(UserRepository userRepository,
                            PasswordEncoder passwordEncoder,
                            AuditService auditService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
        DefaultCodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        verifier.setAllowedTimePeriodDiscrepancy(1);
        this.codeVerifier = verifier;
    }

    /**
     * Генерирует временный секрет и QR-код. Вызывается, когда пользователь начинает enroll.
     * Секрет НЕ сохраняется в БД до подтверждения первого кода.
     */
    public SetupChallenge initiateSetup(AppUser user) {
        String secret = secretGenerator.generate();
        String qrPng = generateQrPngBase64(user.getUsername(), secret);
        return new SetupChallenge(secret, qrPng);
    }

    /**
     * Подтверждение enroll: пользователь ввёл код из приложения.
     * При успехе — сохраняем secret, генерируем backup-коды.
     */
    @Transactional
    public List<String> confirmSetup(UUID userId, String secret, String code, HttpServletRequest http) {
        if (!codeVerifier.isValidCode(secret, code)) {
            auditService.logCurrent(http, AuditActions.MFA_FAILURE, AuditResults.FAIL,
                    "User", userId.toString(), "Invalid code on enrollment");
            throw new IllegalArgumentException("Invalid TOTP code");
        }
        AppUser user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        user.setTotpSecret(secret);
        user.setTotpEnabled(true);
        user.setTotpEnrolledAt(Instant.now());

        List<String> plain = new ArrayList<>(BACKUP_CODES_COUNT);
        StringBuilder hashedJson = new StringBuilder("[");
        for (int i = 0; i < BACKUP_CODES_COUNT; i++) {
            String code10 = generateBackupCode();
            plain.add(code10);
            if (i > 0) hashedJson.append(",");
            hashedJson.append("\"").append(passwordEncoder.encode(code10)).append("\"");
        }
        hashedJson.append("]");
        user.setBackupCodes(hashedJson.toString());

        userRepository.save(user);

        auditService.logCurrent(http, AuditActions.MFA_ENABLED, AuditResults.SUCCESS,
                "User", userId.toString(), "TOTP enrolled, backup codes issued");
        return plain;
    }

    /**
     * Проверка кода при логине. Поддерживает как TOTP-код, так и одноразовый backup-код.
     * При использовании backup-кода — он удаляется из списка.
     */
    @Transactional
    public boolean verify(AppUser user, String code, HttpServletRequest http) {
        if (user.getTotpSecret() == null) {
            return false;
        }

        // 1. Сначала пробуем TOTP
        if (codeVerifier.isValidCode(user.getTotpSecret(), code)) {
            auditService.log(http, user.getId(), user.getUsername(), null,
                    AuditActions.MFA_SUCCESS, AuditResults.SUCCESS,
                    "User", user.getId().toString(), "TOTP verified");
            return true;
        }

        // 2. Backup-код
        if (user.getBackupCodes() != null && tryConsumeBackupCode(user, code)) {
            userRepository.save(user);
            auditService.log(http, user.getId(), user.getUsername(), null,
                    AuditActions.MFA_BACKUP_CODE_USED, AuditResults.SUCCESS,
                    "User", user.getId().toString(), "Backup code used");
            return true;
        }

        auditService.log(http, user.getId(), user.getUsername(), null,
                AuditActions.MFA_FAILURE, AuditResults.FAIL,
                "User", user.getId().toString(), "Invalid MFA code");
        return false;
    }

    @Transactional
    public void disable(UUID userId, HttpServletRequest http) {
        AppUser user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        // Внешним пользователям отключать 2FA нельзя
        if (user.getSource() == AppUser.Source.EXTERNAL) {
            throw new IllegalStateException("MFA is mandatory for EXTERNAL users");
        }
        user.setTotpEnabled(false);
        user.setTotpSecret(null);
        user.setBackupCodes(null);
        user.setTotpEnrolledAt(null);
        userRepository.save(user);
        auditService.logCurrent(http, AuditActions.MFA_DISABLED, AuditResults.SUCCESS,
                "User", userId.toString(), "MFA disabled");
    }

    // ============== private ==============

    private boolean tryConsumeBackupCode(AppUser user, String code) {
        // Простой парсер JSON-массива ["hash1","hash2",...] (без подключения Jackson сюда)
        String json = user.getBackupCodes().trim();
        if (!json.startsWith("[") || !json.endsWith("]")) return false;
        String inner = json.substring(1, json.length() - 1).trim();
        if (inner.isEmpty()) return false;

        String[] parts = inner.split(",");
        List<String> remaining = new ArrayList<>(parts.length);
        boolean matched = false;
        for (String raw : parts) {
            String hash = raw.trim();
            if (hash.startsWith("\"") && hash.endsWith("\"")) {
                hash = hash.substring(1, hash.length() - 1);
            }
            if (!matched && passwordEncoder.matches(code, hash)) {
                matched = true; // используем — не возвращаем в список
                continue;
            }
            remaining.add(hash);
        }
        if (!matched) return false;

        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < remaining.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(remaining.get(i)).append("\"");
        }
        sb.append("]");
        user.setBackupCodes(sb.toString());
        return true;
    }

    private String generateBackupCode() {
        StringBuilder sb = new StringBuilder(BACKUP_CODE_LENGTH + 1);
        for (int i = 0; i < BACKUP_CODE_LENGTH; i++) {
            if (i == 5) sb.append('-');
            sb.append(BACKUP_CODE_CHARSET.charAt(random.nextInt(BACKUP_CODE_CHARSET.length())));
        }
        return sb.toString();
    }

    private String generateQrPngBase64(String username, String secret) {
        QrData data = new QrData.Builder()
                .label(username)
                .secret(secret)
                .issuer(issuer)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();
        try {
            byte[] png = qrGenerator.generate(data);
            return Utils.getDataUriForImage(png, qrGenerator.getImageMimeType());
        } catch (Exception e) {
            throw new IllegalStateException("Cannot generate QR code", e);
        }
    }

    public record SetupChallenge(String secret, String qrCodeDataUri) {
    }
}