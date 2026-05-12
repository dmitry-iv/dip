package com.example.securitycourse.service;

import com.example.securitycourse.repository.AuditLogRepository;
import com.example.securitycourse.repository.IncidentRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;

/**
 * Сервис для построения сводных отчётов и аналитики.
 * Использует прямые SQL-запросы к audit_log и incidents для агрегации.
 */
@Service
@Transactional(readOnly = true)
public class ReportService {

    @PersistenceContext
    private EntityManager em;

    private final AuditLogRepository auditLogRepository;
    private final IncidentRepository incidentRepository;

    public ReportService(AuditLogRepository auditLogRepository,
                         IncidentRepository incidentRepository) {
        this.auditLogRepository = auditLogRepository;
        this.incidentRepository = incidentRepository;
    }

    /**
     * Активность за последние 24 часа: число событий аудита и инцидентов
     * по часам (24 точки).
     */
    public ActivityChartData activityLast24h() {
        Instant since = Instant.now().minusSeconds(24 * 3600);

        // События аудита: группируем по часу
        @SuppressWarnings("unchecked")
        List<Object[]> auditRows = em.createNativeQuery("""
                SELECT EXTRACT(HOUR FROM ts) AS h, COUNT(*) AS c
                FROM audit_log
                WHERE ts >= :since
                GROUP BY EXTRACT(HOUR FROM ts)
                """)
                .setParameter("since", since)
                .getResultList();

        @SuppressWarnings("unchecked")
        List<Object[]> incidentRows = em.createNativeQuery("""
                SELECT EXTRACT(HOUR FROM created_at) AS h, COUNT(*) AS c
                FROM incidents
                WHERE created_at >= :since
                GROUP BY EXTRACT(HOUR FROM created_at)
                """)
                .setParameter("since", since)
                .getResultList();

        long[] auditPerHour = new long[24];
        long[] incidentPerHour = new long[24];

        for (Object[] row : auditRows) {
            int h = ((Number) row[0]).intValue();
            long c = ((Number) row[1]).longValue();
            if (h >= 0 && h < 24) auditPerHour[h] = c;
        }
        for (Object[] row : incidentRows) {
            int h = ((Number) row[0]).intValue();
            long c = ((Number) row[1]).longValue();
            if (h >= 0 && h < 24) incidentPerHour[h] = c;
        }

        // Метки осей "00:00" .. "23:00"
        List<String> labels = new ArrayList<>(24);
        for (int i = 0; i < 24; i++) {
            labels.add(String.format("%02d:00", i));
        }
        return new ActivityChartData(labels, auditPerHour, incidentPerHour);
    }

    /** Распределение событий аудита по категориям (за последние 24 часа). */
    public Map<String, Long> categoryDistribution24h() {
        Instant since = Instant.now().minusSeconds(24 * 3600);

        @SuppressWarnings("unchecked")
        List<Object[]> rows = em.createNativeQuery("""
                SELECT category, COUNT(*) AS c
                FROM audit_log
                WHERE ts >= :since
                GROUP BY category
                ORDER BY c DESC
                """)
                .setParameter("since", since)
                .getResultList();

        Map<String, Long> result = new LinkedHashMap<>();
        for (Object[] row : rows) {
            String cat = row[0] == null ? "UNKNOWN" : row[0].toString();
            result.put(cat, ((Number) row[1]).longValue());
        }
        return result;
    }

    /** Распределение по severity (1..5) за последние 24 часа. */
    public long[] severityDistribution24h() {
        Instant since = Instant.now().minusSeconds(24 * 3600);

        @SuppressWarnings("unchecked")
        List<Object[]> rows = em.createNativeQuery("""
                SELECT severity, COUNT(*) AS c
                FROM audit_log
                WHERE ts >= :since
                GROUP BY severity
                """)
                .setParameter("since", since)
                .getResultList();

        long[] perSev = new long[5]; // index 0..4 → severity 1..5
        for (Object[] row : rows) {
            int sev = ((Number) row[0]).intValue();
            long c = ((Number) row[1]).longValue();
            if (sev >= 1 && sev <= 5) perSev[sev - 1] = c;
        }
        return perSev;
    }

    /** Топ-10 IP по числу событий за последние 24 часа. */
    public List<TopItem> topIpsLast24h() {
        Instant since = Instant.now().minusSeconds(24 * 3600);

        @SuppressWarnings("unchecked")
        List<Object[]> rows = em.createNativeQuery("""
                SELECT ip, COUNT(*) AS c
                FROM audit_log
                WHERE ts >= :since AND ip IS NOT NULL AND ip <> ''
                GROUP BY ip
                ORDER BY c DESC
                LIMIT 10
                """)
                .setParameter("since", since)
                .getResultList();

        List<TopItem> result = new ArrayList<>();
        for (Object[] row : rows) {
            result.add(new TopItem(row[0].toString(), ((Number) row[1]).longValue()));
        }
        return result;
    }

    /** Топ-10 пользователей по числу событий за последние 24 часа. */
    public List<TopItem> topUsersLast24h() {
        Instant since = Instant.now().minusSeconds(24 * 3600);

        @SuppressWarnings("unchecked")
        List<Object[]> rows = em.createNativeQuery("""
                SELECT actor_username, COUNT(*) AS c
                FROM audit_log
                WHERE ts >= :since AND actor_username IS NOT NULL AND actor_username <> ''
                GROUP BY actor_username
                ORDER BY c DESC
                LIMIT 10
                """)
                .setParameter("since", since)
                .getResultList();

        List<TopItem> result = new ArrayList<>();
        for (Object[] row : rows) {
            result.add(new TopItem(row[0].toString(), ((Number) row[1]).longValue()));
        }
        return result;
    }

    /** Распределение инцидентов по правилам корреляции. */
    public List<TopItem> topRulesAllTime() {
        @SuppressWarnings("unchecked")
        List<Object[]> rows = em.createNativeQuery("""
                SELECT rule_name, COUNT(*) AS c
                FROM incidents
                GROUP BY rule_name
                ORDER BY c DESC
                LIMIT 10
                """)
                .getResultList();

        List<TopItem> result = new ArrayList<>();
        for (Object[] row : rows) {
            result.add(new TopItem(row[0].toString(), ((Number) row[1]).longValue()));
        }
        return result;
    }

    /** Распределение инцидентов по статусу. */
    public Map<String, Long> incidentStatusDistribution() {
        @SuppressWarnings("unchecked")
        List<Object[]> rows = em.createNativeQuery("""
                SELECT status, COUNT(*) AS c
                FROM incidents
                GROUP BY status
                """)
                .getResultList();

        Map<String, Long> result = new LinkedHashMap<>();
        for (Object[] row : rows) {
            result.put(row[0].toString(), ((Number) row[1]).longValue());
        }
        return result;
    }

    /** Сводные числа для шапки отчёта. */
    public ReportSummary summary() {
        long totalAudit = auditLogRepository.count();
        long totalIncidents = incidentRepository.count();
        Instant since24h = Instant.now().minusSeconds(24 * 3600);
        long incidents24h = incidentRepository.countBySeverityGreaterThanEqualAndCreatedAtAfter(1, since24h);
        long highSev24h = incidentRepository.countBySeverityGreaterThanEqualAndCreatedAtAfter(4, since24h);
        return new ReportSummary(totalAudit, totalIncidents, incidents24h, highSev24h);
    }

    public record ActivityChartData(List<String> labels, long[] auditPerHour, long[] incidentPerHour) {}
    public record TopItem(String name, long count) {}
    public record ReportSummary(long totalAudit, long totalIncidents,
                                long incidents24h, long highSeverity24h) {}
}