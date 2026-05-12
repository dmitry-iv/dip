package com.example.securitycourse.service;

import com.example.securitycourse.domain.AuditLog;
import com.example.securitycourse.domain.Incident;
import com.example.securitycourse.repository.AuditLogRepository;
import com.example.securitycourse.repository.IncidentRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * Сервис для страницы /me — личная активность пользователя.
 * Возвращает только записи, относящиеся к текущему пользователю.
 */
@Service
@Transactional(readOnly = true)
public class MyActivityService {

    @PersistenceContext
    private EntityManager em;

    private final AuditLogRepository auditLogRepository;
    private final IncidentRepository incidentRepository;

    public MyActivityService(AuditLogRepository auditLogRepository,
                             IncidentRepository incidentRepository) {
        this.auditLogRepository = auditLogRepository;
        this.incidentRepository = incidentRepository;
    }

    /** Сводные показатели для шапки страницы /me. */
    public MyStats myStats(String username) {
        Instant since30d = Instant.now().minusSeconds(30L * 24 * 3600);

        @SuppressWarnings("unchecked")
        List<Object[]> rows = em.createNativeQuery("""
                SELECT
                    COUNT(*) FILTER (WHERE action = 'LOGIN_SUCCESS') AS logins,
                    COUNT(*) FILTER (WHERE action = 'LOGIN_FAILURE') AS failed,
                    MAX(ts) FILTER (WHERE action = 'LOGIN_SUCCESS') AS last_login,
                    (SELECT ip FROM audit_log
                     WHERE actor_username = :u AND action = 'LOGIN_SUCCESS' AND ts > :since
                     ORDER BY ts DESC LIMIT 1) AS last_ip
                FROM audit_log
                WHERE actor_username = :u AND ts > :since
                """)
                .setParameter("u", username)
                .setParameter("since", since30d)
                .getResultList();

        long logins = 0, failed = 0;
        Instant lastLogin = null;
        String lastIp = null;
        if (!rows.isEmpty() && rows.get(0) != null) {
            Object[] r = rows.get(0);
            logins = r[0] == null ? 0 : ((Number) r[0]).longValue();
            failed = r[1] == null ? 0 : ((Number) r[1]).longValue();
            if (r[2] instanceof Instant i) lastLogin = i;
            if (r[3] != null) lastIp = r[3].toString();
        }

        long incidentsAboutMe = incidentRepository.countByAffectedUserAndCreatedAtAfter(username, since30d);

        return new MyStats(logins, failed, lastLogin, lastIp, incidentsAboutMe);
    }

    /** Последние 20 записей по этому пользователю — для таблицы "мои входы". */
    @SuppressWarnings("unchecked")
    public List<Object[]> myRecentLogins(String username) {
        return em.createNativeQuery("""
                SELECT ts, action, result, ip, user_agent
                FROM audit_log
                WHERE actor_username = :u
                  AND action IN ('LOGIN_SUCCESS','LOGIN_FAILURE','LOGOUT','MFA_SUCCESS','MFA_FAILURE')
                ORDER BY ts DESC
                LIMIT 20
                """)
                .setParameter("u", username)
                .getResultList();
    }

    /** Инциденты которые касаются этого пользователя. */
    public List<Incident> myIncidents(String username) {
        return incidentRepository.findTop20ByAffectedUserOrderByCreatedAtDesc(username);
    }

    public record MyStats(long loginsLast30d, long failedLoginsLast30d,
                          Instant lastLoginAt, String lastLoginIp,
                          long incidentsAboutMeLast30d) {}
}