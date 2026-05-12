package com.example.securitycourse.service;

import com.example.securitycourse.domain.AlertSettings;
import com.example.securitycourse.repository.AlertSettingsRepository;
import jakarta.mail.MessagingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Properties;

/**
 * Управляет настройками SMTP и алертов, хранящимися в БД.
 * Пароль SMTP в БД хранится зашифрованным AES-GCM (см. EncryptionService).
 */
@Service
public class AlertSettingsService {

    private static final Logger log = LoggerFactory.getLogger(AlertSettingsService.class);

    private final AlertSettingsRepository repository;
    private final EncryptionService encryptionService;

    public AlertSettingsService(AlertSettingsRepository repository,
                                EncryptionService encryptionService) {
        this.repository = repository;
        this.encryptionService = encryptionService;
    }

    /**
     * Загружает настройки. Пароль в возвращаемом объекте — РАСШИФРОВАН (plaintext).
     * Возвращается копия, а не сама entity, чтобы случайно не сохранить
     * plaintext в БД.
     */
    @Transactional(readOnly = true)
    public AlertSettings load() {
        AlertSettings s = repository.findById((short) 1)
                .orElseGet(() -> {
                    AlertSettings empty = new AlertSettings();
                    empty.setId((short) 1);
                    return empty;
                });
        AlertSettings copy = copyOf(s);
        try {
            copy.setSmtpPassword(encryptionService.decrypt(s.getSmtpPassword()));
        } catch (Exception e) {
            log.error("Failed to decrypt SMTP password — corrupted data or wrong key. " +
                    "Resetting password to empty.", e);
            copy.setSmtpPassword("");
        }
        return copy;
    }

    @Transactional
    public AlertSettings save(AlertSettings updated) {
        AlertSettings existing = repository.findById((short) 1)
                .orElseGet(() -> {
                    AlertSettings s = new AlertSettings();
                    s.setId((short) 1);
                    return s;
                });
        existing.setSmtpHost(blankToDefault(updated.getSmtpHost(), "smtp.yandex.ru"));
        existing.setSmtpPort(updated.getSmtpPort() == null ? 587 : updated.getSmtpPort());
        existing.setSmtpUsername(nz(updated.getSmtpUsername()));

        // Пустой пароль в форме = "не менять", сохраняем старый зашифрованный.
        // Непустой = шифруем и кладём.
        if (updated.getSmtpPassword() != null && !updated.getSmtpPassword().isBlank()) {
            existing.setSmtpPassword(encryptionService.encrypt(updated.getSmtpPassword().trim()));
        }

        existing.setSenderAddress(nz(updated.getSenderAddress()));
        existing.setRecipientsCsv(nz(updated.getRecipientsCsv()));
        existing.setMinSeverity(updated.getMinSeverity() == null ? 4 : updated.getMinSeverity());
        existing.setThrottleSeconds(updated.getThrottleSeconds() == null ? 60 : updated.getThrottleSeconds());
        existing.setEnabled(Boolean.TRUE.equals(updated.getEnabled()));
        return repository.save(existing);
    }

    /** Создаёт MailSender по текущим настройкам. STARTTLS на порту 587. */
    public JavaMailSender buildMailSender(AlertSettings s) {
        JavaMailSenderImpl sender = new JavaMailSenderImpl();
        sender.setHost(s.getSmtpHost());
        sender.setPort(s.getSmtpPort());
        sender.setUsername(s.getSmtpUsername());
        sender.setPassword(s.getSmtpPassword()); // plaintext, уже расшифрован в load()
        sender.setDefaultEncoding("UTF-8");

        Properties p = sender.getJavaMailProperties();
        p.put("mail.transport.protocol", "smtp");
        p.put("mail.smtp.auth", "true");
        p.put("mail.smtp.starttls.enable", "true");
        p.put("mail.smtp.starttls.required", "true");
        p.put("mail.smtp.connectiontimeout", "10000");
        p.put("mail.smtp.timeout", "10000");
        p.put("mail.smtp.writetimeout", "10000");
        return sender;
    }

    public void testConnection(AlertSettings s) throws MessagingException {
        JavaMailSenderImpl sender = (JavaMailSenderImpl) buildMailSender(s);
        sender.testConnection();
    }

    public void sendTestEmail(AlertSettings s) throws Exception {
        List<String> to = parseRecipients(s.getRecipientsCsv());
        if (to.isEmpty()) {
            throw new IllegalStateException("Список получателей пуст");
        }
        if (s.getSenderAddress() == null || s.getSenderAddress().isBlank()) {
            throw new IllegalStateException("Не задан адрес отправителя");
        }

        JavaMailSender sender = buildMailSender(s);
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setFrom(s.getSenderAddress());
        msg.setTo(to.toArray(new String[0]));
        msg.setSubject("[CorpSec] Тестовое письмо настройки алертов");
        msg.setText("""
                Это тестовое письмо из системы мониторинга ИБ CorpSec.

                Если вы получили это сообщение, значит настройки SMTP корректны
                и алерты об инцидентах будут приходить на этот адрес.

                --
                Корпоративная система мониторинга ИБ
                """);
        sender.send(msg);
        log.info("Test email sent to: {}", String.join(", ", to));
    }

    public static List<String> parseRecipients(String csv) {
        if (csv == null || csv.isBlank()) return List.of();
        return List.of(csv.split("\\s*[,;]\\s*")).stream()
                .filter(s -> !s.isBlank())
                .toList();
    }

    private static AlertSettings copyOf(AlertSettings src) {
        AlertSettings dst = new AlertSettings();
        dst.setId(src.getId());
        dst.setSmtpHost(src.getSmtpHost());
        dst.setSmtpPort(src.getSmtpPort());
        dst.setSmtpUsername(src.getSmtpUsername());
        dst.setSmtpPassword(src.getSmtpPassword());
        dst.setSenderAddress(src.getSenderAddress());
        dst.setRecipientsCsv(src.getRecipientsCsv());
        dst.setMinSeverity(src.getMinSeverity());
        dst.setThrottleSeconds(src.getThrottleSeconds());
        dst.setEnabled(src.getEnabled());
        dst.setUpdatedAt(src.getUpdatedAt());
        return dst;
    }

    private static String nz(String s) { return s == null ? "" : s.trim(); }
    private static String blankToDefault(String s, String d) {
        return (s == null || s.isBlank()) ? d : s.trim();
    }
}