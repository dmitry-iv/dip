package com.example.securitycourse.repository;

import com.example.securitycourse.domain.Incident;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface IncidentRepository extends JpaRepository<Incident, UUID> {

    long countByStatus(Incident.Status status);

    long countBySeverityGreaterThanEqualAndCreatedAtAfter(int severity, Instant after);

    Optional<Incident> findFirstByRuleNameAndAffectedUserAndStatusOrderByCreatedAtDesc(
            String ruleName, String affectedUser, Incident.Status status);

    Optional<Incident> findFirstByRuleNameAndSourceIpAndStatusOrderByCreatedAtDesc(
            String ruleName, String sourceIp, Incident.Status status);

    List<Incident> findTop20ByOrderByCreatedAtDesc();

    // ===== Запросы для SOC-панели =====

    /** Очередь "новых" инцидентов — в порядке убывания severity, потом по времени. */
    List<Incident> findTop50ByStatusOrderBySeverityDescCreatedAtDesc(Incident.Status status);

    /** "Мои" инциденты — назначенные на аналитика, в работе. */
    List<Incident> findByAssignedUserIdAndStatusInOrderByCreatedAtDesc(
            UUID assignedUserId, List<Incident.Status> statuses);

    /** Все инциденты назначенные на пользователя (любой статус). */
    long countByAssignedUserIdAndStatus(UUID assignedUserId, Incident.Status status);

    /** Сколько решений сделал аналитик за период. */
    long countByAssignedUserIdAndStatusInAndResolvedAtAfter(
            UUID assignedUserId, List<Incident.Status> statuses, Instant after);

    /** Все инциденты которые касаются конкретного пользователя (для страницы /me). */
    List<Incident> findTop20ByAffectedUserOrderByCreatedAtDesc(String affectedUser);

    long countByAffectedUserAndCreatedAtAfter(String affectedUser, Instant after);
}