package com.example.securitycourse.repository;

import com.example.securitycourse.domain.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID>, JpaSpecificationExecutor<AuditLog> {
    Page<AuditLog> findAllByActorUsernameContainingIgnoreCase(String actorUsername, Pageable pageable);
}
