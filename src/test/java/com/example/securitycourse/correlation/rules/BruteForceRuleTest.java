package com.example.securitycourse.correlation.rules;

import com.example.securitycourse.audit.AuditCategory;
import com.example.securitycourse.audit.AuditEventCreated;
import com.example.securitycourse.correlation.IncidentDraft;
import com.example.securitycourse.repository.AuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

/**
 * Тесты правила корреляции BRUTE_FORCE.
 * Проверяют: триггер только на LOGIN_FAILURE, пропуск без IP,
 * срабатывание при достижении порога, корректное формирование инцидента.
 */
@DisplayName("BruteForceRule — обнаружение подбора пароля (MITRE T1110)")
class BruteForceRuleTest {

    private BruteForceRule rule;
    private AuditLogRepository repository;

    @BeforeEach
    void setUp() {
        rule = new BruteForceRule();
        ReflectionTestUtils.setField(rule, "threshold", 5);
        ReflectionTestUtils.setField(rule, "windowMinutes", 5);
        repository = Mockito.mock(AuditLogRepository.class);
        // По умолчанию пустой список связанных логов
        when(repository.findRecentByIpAndAction(anyString(), anyString(), any(Instant.class)))
                .thenReturn(Collections.emptyList());
    }

    @Test
    @DisplayName("Правило срабатывает: 5+ LOGIN_FAILURE с одного IP создают инцидент")
    void fires_whenThresholdReached() {
        when(repository.countByIpAndActionAndTimestampAfter(eq("10.0.0.1"), eq("LOGIN_FAILURE"), any()))
                .thenReturn(5L);

        Optional<IncidentDraft> result = rule.evaluate(makeEvent("LOGIN_FAILURE", "alice", "10.0.0.1"), repository);

        assertTrue(result.isPresent(), "Rule must fire when failure count >= threshold");
        IncidentDraft draft = result.get();
        assertEquals("BRUTE_FORCE", draft.ruleName());
        assertEquals(5, draft.severity());
        assertEquals("10.0.0.1", draft.sourceIp());
        assertEquals("T1110", draft.mitreTechnique());
    }

    @Test
    @DisplayName("Правило не срабатывает: 4 LOGIN_FAILURE ниже порога")
    void doesNotFire_belowThreshold() {
        when(repository.countByIpAndActionAndTimestampAfter(anyString(), anyString(), any()))
                .thenReturn(4L);

        Optional<IncidentDraft> result = rule.evaluate(makeEvent("LOGIN_FAILURE", "alice", "10.0.0.1"), repository);

        assertFalse(result.isPresent(), "Below threshold must not generate incident");
    }

    @Test
    @DisplayName("Правило игнорирует не-LOGIN_FAILURE действия")
    void ignores_nonLoginFailureActions() {
        // Даже если у нас 100 событий LOGIN_SUCCESS, brute-force их не должно касаться
        when(repository.countByIpAndActionAndTimestampAfter(anyString(), anyString(), any()))
                .thenReturn(100L);

        Optional<IncidentDraft> result = rule.evaluate(makeEvent("LOGIN_SUCCESS", "alice", "10.0.0.1"), repository);

        assertFalse(result.isPresent(), "BruteForce rule must only process LOGIN_FAILURE events");
    }

    @Test
    @DisplayName("Правило игнорирует события без IP")
    void ignores_eventsWithoutIp() {
        Optional<IncidentDraft> result1 = rule.evaluate(makeEvent("LOGIN_FAILURE", "alice", null), repository);
        Optional<IncidentDraft> result2 = rule.evaluate(makeEvent("LOGIN_FAILURE", "alice", ""), repository);

        assertFalse(result1.isPresent());
        assertFalse(result2.isPresent());
    }

    @Test
    @DisplayName("Описание инцидента содержит количество попыток, IP и окно")
    void incidentDescription_isMeaningful() {
        when(repository.countByIpAndActionAndTimestampAfter(anyString(), anyString(), any()))
                .thenReturn(7L);

        Optional<IncidentDraft> result = rule.evaluate(makeEvent("LOGIN_FAILURE", "alice", "10.0.0.5"), repository);

        assertTrue(result.isPresent());
        String desc = result.get().description();
        assertTrue(desc.contains("7"), "Description must contain attempt count");
        assertTrue(desc.contains("10.0.0.5"), "Description must contain source IP");
        assertTrue(desc.contains("5"), "Description must contain window minutes");
    }

    private AuditEventCreated makeEvent(String action, String username, String ip) {
        return new AuditEventCreated(
                UUID.randomUUID(),
                Instant.now(),
                null,
                username,
                action,
                AuditCategory.AUTH,
                3,
                "FAIL",
                "User",
                null,
                ip,
                "test-agent",
                "Test login attempt"
        );
    }
}