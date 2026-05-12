package com.example.securitycourse.config;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditResults;
import com.example.securitycourse.service.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Логирует системные события приложения (старт, остановка) в журнал аудита.
 * Эти записи попадают в hash-цепочку и видны в категории SYSTEM на дашборде.
 *
 * Помогает обнаружить случаи перезапуска приложения злоумышленником
 * (например, чтобы обойти runtime-проверки или сбросить кэш).
 */
@Component
public class SystemEventsListener {

    private static final Logger log = LoggerFactory.getLogger(SystemEventsListener.class);

    private final AuditService auditService;

    public SystemEventsListener(AuditService auditService) {
        this.auditService = auditService;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onAppStarted(ApplicationReadyEvent event) {
        try {
            String version = event.getSpringApplication().getMainApplicationClass() != null
                    ? event.getSpringApplication().getMainApplicationClass().getPackage().getImplementationVersion()
                    : null;
            String hostname;
            try {
                hostname = java.net.InetAddress.getLocalHost().getHostName();
            } catch (Exception e) {
                hostname = "unknown";
            }
            auditService.log(null, null, "system", "ROLE_SYSTEM",
                    AuditActions.APP_STARTED, AuditResults.INFO,
                    "Application", "CorpSec",
                    String.format("Application started on host '%s' (Java %s, profile=%s)",
                            hostname,
                            System.getProperty("java.version"),
                            String.join(",", event.getSpringApplication().getAdditionalProfiles())));
            log.info("System event APP_STARTED logged to audit");
        } catch (Exception e) {
            log.warn("Failed to log APP_STARTED event: {}", e.getMessage());
        }
    }

    @EventListener(ContextClosedEvent.class)
    public void onAppStopped(ContextClosedEvent event) {
        try {
            auditService.log(null, null, "system", "ROLE_SYSTEM",
                    AuditActions.APP_STOPPED, AuditResults.INFO,
                    "Application", "CorpSec",
                    "Application shutdown signal received");
            log.info("System event APP_STOPPED logged to audit");
        } catch (Exception e) {
            log.warn("Failed to log APP_STOPPED event: {}", e.getMessage());
        }
    }
}