package com.example.securitycourse.repository;

import com.example.securitycourse.domain.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID>, JpaSpecificationExecutor<AuditLog> {

    Page<AuditLog> findAllByActorUsernameContainingIgnoreCase(String actorUsername, Pageable pageable);

    // ===== Запросы для движка корреляции =====

    long countByIpAndActionAndTimestampAfter(String ip, String action, Instant after);

    long countByActorUsernameAndActionAndTimestampAfter(String actorUsername, String action, Instant after);

    @Query("""
           SELECT COUNT(DISTINCT a.actorUsername)
           FROM AuditLog a
           WHERE a.ip = :ip
             AND a.action = :action
             AND a.timestamp > :after
           """)
    long countDistinctUsersByIpAndAction(@Param("ip") String ip,
                                         @Param("action") String action,
                                         @Param("after") Instant after);

    @Query("""
           SELECT a FROM AuditLog a
           WHERE a.ip = :ip AND a.action = :action AND a.timestamp > :after
           ORDER BY a.timestamp DESC
           """)
    List<AuditLog> findRecentByIpAndAction(@Param("ip") String ip,
                                           @Param("action") String action,
                                           @Param("after") Instant after);

    @Query("""
           SELECT a FROM AuditLog a
           WHERE a.actorUsername = :user AND a.action = :action AND a.timestamp > :after
           ORDER BY a.timestamp DESC
           """)
    List<AuditLog> findRecentByUserAndAction(@Param("user") String user,
                                             @Param("action") String action,
                                             @Param("after") Instant after);

    /**
     * Возвращает все записи в порядке их создания. Сортируем по timestamp
     * (микросекундная точность), id используется как стабильный tiebreaker
     * на случай двух записей в одну микросекунду.
     */
    @Query(value = "SELECT * FROM audit_log ORDER BY ts ASC, id ASC", nativeQuery = true)
    List<AuditLog> findAllOrderedBySeq();
}