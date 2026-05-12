package com.example.securitycourse.service;

import com.example.securitycourse.domain.AlertSettings;
import com.example.securitycourse.domain.Incident;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Отправляет email-уведомления при создании инцидентов с высоким уровнем критичности.
 * Все настройки SMTP и получатели берутся из БД (таблица alert_settings)
 * через AlertSettingsService — изменяются на странице /admin/alert-settings.
 *
 * Защищён троттлингом: одно правило не может породить больше одного письма
 * в N секунд (защита от шторма).
 */
@Service
public class AlertingService {

    private static final Logger log = LoggerFactory.getLogger(AlertingService.class);

    private final AlertSettingsService alertSettingsService;

    /** key = ruleName, value = последний момент отправки. */
    private final Map<String, Instant> lastSent = new ConcurrentHashMap<>();

    public AlertingService(AlertSettingsService alertSettingsService) {
        this.alertSettingsService = alertSettingsService;
    }

    @EventListener
    @Async("alertExecutor")
    @Transactional
    public void onIncidentCreated(IncidentService.IncidentCreatedEvent event) {
        Incident i = event.incident();

        AlertSettings s;
        try {
            s = alertSettingsService.load();
        } catch (Exception e) {
            log.warn("Cannot load alert settings: {}", e.getMessage());
            return;
        }

        if (!Boolean.TRUE.equals(s.getEnabled())) {
            log.debug("Alerting is disabled in settings");
            return;
        }
        if (i.getSeverity() < s.getMinSeverity()) {
            return;
        }

        List<String> recipients = AlertSettingsService.parseRecipients(s.getRecipientsCsv());
        if (recipients.isEmpty()) {
            log.warn("No alert recipients configured — skipping incident {}", i.getId());
            return;
        }
        if (s.getSenderAddress() == null || s.getSenderAddress().isBlank()) {
            log.warn("Sender address is empty — skipping incident {}", i.getId());
            return;
        }
        if (s.getSmtpUsername() == null || s.getSmtpUsername().isBlank()
                || s.getSmtpPassword() == null || s.getSmtpPassword().isBlank()) {
            log.warn("SMTP credentials are not configured — skipping incident {}", i.getId());
            return;
        }

        // Throttle
        int throttle = s.getThrottleSeconds() == null ? 60 : s.getThrottleSeconds();
        Instant prev = lastSent.get(i.getRuleName());
        if (prev != null && prev.isAfter(Instant.now().minus(Duration.ofSeconds(throttle)))) {
            log.info("Alert throttled for rule {} (last sent at {})", i.getRuleName(), prev);
            return;
        }

        try {
            JavaMailSender mailSender = alertSettingsService.buildMailSender(s);
            SimpleMailMessage msg = new SimpleMailMessage();
            msg.setFrom(s.getSenderAddress());
            msg.setTo(recipients.toArray(new String[0]));
            msg.setSubject(buildSubject(i));
            msg.setText(buildBody(i));
            mailSender.send(msg);
            lastSent.put(i.getRuleName(), Instant.now());
            log.info("Alert email sent for incident {} (rule={}, severity={})",
                    i.getId(), i.getRuleName(), i.getSeverity());
        } catch (Exception ex) {
            log.error("Failed to send alert for incident {}: {}", i.getId(), ex.getMessage(), ex);
        }
    }

    private String buildSubject(Incident i) {
        return String.format("[CorpSec][SEV-%d] %s — %s",
                i.getSeverity(),
                i.getRuleName(),
                i.getAffectedUser() != null ? "user=" + i.getAffectedUser()
                        : (i.getSourceIp() != null ? "ip=" + i.getSourceIp() : ""));
    }

    private String buildBody(Incident i) {
        StringBuilder b = new StringBuilder();
        b.append("=== Инцидент информационной безопасности ===\n\n");
        b.append("ID:         ").append(i.getId()).append("\n");
        b.append("Время:      ").append(i.getCreatedAt()).append("\n");
        b.append("Правило:    ").append(i.getRuleName()).append("\n");
        b.append("Severity:   ").append(i.getSeverity()).append(" / 5\n");
        b.append("Статус:     ").append(i.getStatus()).append("\n");
        if (i.getMitreTechnique() != null) {
            b.append("MITRE:      ").append(i.getMitreTechnique()).append("\n");
        }
        if (i.getAffectedUser() != null) {
            b.append("User:       ").append(i.getAffectedUser()).append("\n");
        }
        if (i.getSourceIp() != null) {
            b.append("IP:         ").append(i.getSourceIp()).append("\n");
        }
        b.append("\nОписание:\n").append(i.getDescription()).append("\n\n");
        b.append("Ссылка: http://localhost:8080/incidents/").append(i.getId()).append("\n");
        b.append("\n--\nКорпоративная система мониторинга ИБ\n");
        return b.toString();
    }
}