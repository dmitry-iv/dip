package com.example.securitycourse.service;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditCategory;
import com.example.securitycourse.audit.AuditResults;
import com.example.securitycourse.correlation.IncidentDraft;
import com.example.securitycourse.domain.AuditLog;
import com.example.securitycourse.domain.Incident;
import com.example.securitycourse.repository.AuditLogRepository;
import com.example.securitycourse.repository.IncidentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Random;

/**
 * Генератор демо-данных. Создаёт реалистичную картину активности SOC.
 * Все записи помечаются префиксом DEMO_MARKER в details/description.
 */
@Service
public class DemoDataService {

    private static final Logger log = LoggerFactory.getLogger(DemoDataService.class);

    public static final String DEMO_MARKER = "[DEMO]";

    private final AuditService auditService;
    private final IncidentService incidentService;
    private final AuditLogRepository auditLogRepository;
    private final IncidentRepository incidentRepository;

    private final Random rnd = new Random();

    private static final String[] DEMO_USERS = {
            "alice.smith", "bob.johnson", "charlie.brown", "diana.prince",
            "eve.wilson", "frank.miller", "grace.lee", "henry.davis"
    };

    private static final String[] DEMO_IPS = {
            "10.0.1.45", "10.0.1.67", "10.0.2.103", "10.0.2.118",
            "192.168.1.5", "192.168.1.42", "172.16.0.88", "172.16.0.91",
            "203.0.113.23", "203.0.113.77", "198.51.100.14", "45.155.205.233"
    };

    public DemoDataService(AuditService auditService,
                           IncidentService incidentService,
                           AuditLogRepository auditLogRepository,
                           IncidentRepository incidentRepository) {
        this.auditService = auditService;
        this.incidentService = incidentService;
        this.auditLogRepository = auditLogRepository;
        this.incidentRepository = incidentRepository;
    }

    public GenerationReport generate() {
        int audits = 0;
        int incidents = 0;

        log.info("Demo data generation started");

        // 1) Успешные логины
        for (int i = 0; i < 25; i++) {
            String user = pick(DEMO_USERS);
            String ip = pick(DEMO_IPS);
            writeAudit(user, "ROLE_USER", AuditActions.LOGIN_SUCCESS, AuditResults.SUCCESS,
                    "User", null, ip,
                    DEMO_MARKER + " Successful login from " + ip);
            audits++;
        }

        // 2) Доступ к чувствительным данным
        for (int i = 0; i < 18; i++) {
            String user = pick(DEMO_USERS);
            String ip = pick(DEMO_IPS);
            writeAudit(user, "ROLE_USER", AuditActions.SENSITIVE_DATA_ACCESS, AuditResults.SUCCESS,
                    "Document", "doc-" + (1000 + rnd.nextInt(900)), ip,
                    DEMO_MARKER + " Accessed sensitive document");
            audits++;
        }

        // 3) Неудачные попытки входа
        for (int i = 0; i < 8; i++) {
            String user = pick(DEMO_USERS);
            String ip = pick(DEMO_IPS);
            writeAudit(user, null, AuditActions.LOGIN_FAILURE, AuditResults.FAIL,
                    "User", null, ip,
                    DEMO_MARKER + " Wrong password from " + ip);
            audits++;
        }

        // 4) Изменения пользователей
        for (int i = 0; i < 5; i++) {
            String target = pick(DEMO_USERS);
            String ip = pick(new String[]{"10.0.1.45", "10.0.1.67", "192.168.1.5"});
            writeAudit("admin", "ROLE_ADMIN", AuditActions.USER_UPDATED, AuditResults.SUCCESS,
                    "User", target, ip,
                    DEMO_MARKER + " Updated user roles for " + target);
            audits++;
        }

        // 5) Экспорт данных
        for (int i = 0; i < 4; i++) {
            String user = pick(new String[]{"alice.smith", "bob.johnson"});
            String ip = pick(DEMO_IPS);
            writeAudit(user, "ROLE_MANAGER", AuditActions.DATA_EXPORT, AuditResults.SUCCESS,
                    "Report", "report-q1", ip,
                    DEMO_MARKER + " Exported quarterly report");
            audits++;
        }

        // ===== ИНЦИДЕНТЫ =====
        // Порядок IncidentDraft: ruleName, ruleDescription, severity, affectedUser,
        //   sourceIp, description, relatedLogIds, mitreTechnique

        incidentService.createIncident(new IncidentDraft(
                "BRUTE_FORCE",
                "5+ неудачных попыток входа с одного IP за 5 минут",
                5, "eve.wilson", "45.155.205.233",
                DEMO_MARKER + " Обнаружено 12 неудачных попыток входа в учётную запись 'eve.wilson' с IP 45.155.205.233 за 4 минуты. Возможна атака подбором пароля.",
                List.of(), "T1110"
        ));
        incidents++;

        incidentService.createIncident(new IncidentDraft(
                "CREDENTIAL_STUFFING",
                "Попытки входа с одного IP под разными учётными записями",
                4, null, "203.0.113.77",
                DEMO_MARKER + " Один IP 203.0.113.77 пытался войти под 7 разными учётными записями за 10 минут. Признак credential stuffing атаки с использованием утечки.",
                List.of(), "T1110.004"
        ));
        incidents++;

        incidentService.createIncident(new IncidentDraft(
                "MFA_BYPASS_ATTEMPT",
                "Многократный ввод неверного TOTP-кода",
                4, "frank.miller", "10.0.2.118",
                DEMO_MARKER + " Пользователь 'frank.miller' ввёл 8 раз подряд неверный код 2FA. Возможна попытка обхода MFA или кража устройства.",
                List.of(), "T1621"
        ));
        incidents++;

        incidentService.createIncident(new IncidentDraft(
                "MASS_EXPORT",
                "Аномальное число операций экспорта",
                3, "henry.davis", "10.0.1.67",
                DEMO_MARKER + " Пользователь 'henry.davis' за 10 минут экспортировал 15 отчётов. В среднем за день экспортирует 2-3. Возможна утечка данных.",
                List.of(), "T1567"
        ));
        incidents++;

        incidentService.createIncident(new IncidentDraft(
                "PRIVILEGE_ESCALATION",
                "Назначение административной роли пользователю",
                4, "charlie.brown", "10.0.1.45",
                DEMO_MARKER + " Учётной записи 'charlie.brown' назначена роль ADMIN. Эскалация привилегий должна сопровождаться согласованием.",
                List.of(), "T1098"
        ));
        incidents++;

        incidentService.createIncident(new IncidentDraft(
                "OFF_HOURS_LOGIN",
                "Вход в нерабочее время",
                3, "grace.lee", "172.16.0.91",
                DEMO_MARKER + " Пользователь 'grace.lee' выполнил вход в 03:14 — нерабочее время для роли BUSINESS_USER.",
                List.of(), "T1078"
        ));
        incidents++;

        log.info("Demo data generation finished: {} audit events, {} incidents", audits, incidents);
        return new GenerationReport(audits, incidents);
    }

    private void writeAudit(String username, String roles, AuditActions action, AuditResults result,
                            String entityType, String entityId, String ip, String details) {
        FakeRequest req = new FakeRequest(ip, "DemoGenerator/1.0");
        auditService.log(req, null, username, roles, action, result, entityType, entityId, details);
    }

    @Transactional
    public CleanupReport cleanup() {
        log.info("Demo data cleanup started");

        List<Incident> demoIncidents = incidentRepository.findAll().stream()
                .filter(i -> i.getDescription() != null && i.getDescription().contains(DEMO_MARKER))
                .toList();
        int deletedIncidents = demoIncidents.size();
        incidentRepository.deleteAll(demoIncidents);

        List<AuditLog> demoAudits = auditLogRepository.findAll().stream()
                .filter(a -> a.getDetails() != null && a.getDetails().contains(DEMO_MARKER))
                .toList();
        int deletedAudits = demoAudits.size();
        auditLogRepository.deleteAll(demoAudits);

        log.info("Demo data cleanup finished: {} audit events, {} incidents removed",
                deletedAudits, deletedIncidents);
        return new CleanupReport(deletedAudits, deletedIncidents);
    }

    private String pick(String[] arr) { return arr[rnd.nextInt(arr.length)]; }

    public record GenerationReport(int auditEventsCreated, int incidentsCreated) {}
    public record CleanupReport(int auditEventsRemoved, int incidentsRemoved) {}
}