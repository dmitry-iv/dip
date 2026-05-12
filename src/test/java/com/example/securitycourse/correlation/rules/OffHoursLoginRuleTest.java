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

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты правила корреляции OFF_HOURS_LOGIN.
 * Проверяют: срабатывание в ночные часы, пропуск в рабочие часы,
 * правильную обработку wrap-around (20:00 - 07:00 через полночь),
 * игнорирование не-LOGIN_SUCCESS событий.
 */
@DisplayName("OffHoursLoginRule — вход в нерабочее время (MITRE T1078)")
class OffHoursLoginRuleTest {

    private OffHoursLoginRule rule;
    private AuditLogRepository repository;

    @BeforeEach
    void setUp() {
        rule = new OffHoursLoginRule();
        ReflectionTestUtils.setField(rule, "offHoursStart", 20); // 20:00
        ReflectionTestUtils.setField(rule, "offHoursEnd", 7);    // до 07:00
        repository = Mockito.mock(AuditLogRepository.class);
    }

    @Test
    @DisplayName("Срабатывает на вход в 23:30 — посреди ночи")
    void fires_atMidnight() {
        Optional<IncidentDraft> result = rule.evaluate(
                makeLoginAt(23, 30), repository);

        assertTrue(result.isPresent(), "Login at 23:30 must trigger off-hours rule");
        assertEquals("OFF_HOURS_LOGIN", result.get().ruleName());
        assertEquals(3, result.get().severity());
        assertEquals("T1078", result.get().mitreTechnique());
    }

    @Test
    @DisplayName("Срабатывает на вход в 03:00 — глубокой ночью")
    void fires_atEarlyMorning() {
        Optional<IncidentDraft> result = rule.evaluate(makeLoginAt(3, 0), repository);

        assertTrue(result.isPresent(), "Login at 03:00 must trigger");
    }

    @Test
    @DisplayName("Срабатывает на границе: вход ровно в 20:00")
    void fires_atExactStartOfOffHours() {
        Optional<IncidentDraft> result = rule.evaluate(makeLoginAt(20, 0), repository);

        assertTrue(result.isPresent(), "Login at exactly 20:00 must trigger (inclusive)");
    }

    @Test
    @DisplayName("Не срабатывает в 06:59 — последняя минута off-hours, должна попасть")
    void fires_at0659() {
        Optional<IncidentDraft> result = rule.evaluate(makeLoginAt(6, 59), repository);

        assertTrue(result.isPresent(), "Login at 06:59 (last minute of off-hours) must trigger");
    }

    @Test
    @DisplayName("НЕ срабатывает на вход в рабочее время (10:00)")
    void doesNotFire_duringWorkHours() {
        Optional<IncidentDraft> result = rule.evaluate(makeLoginAt(10, 0), repository);

        assertFalse(result.isPresent(), "Login at 10:00 (work hours) must not trigger");
    }

    @Test
    @DisplayName("НЕ срабатывает на вход в 14:30 — середина рабочего дня")
    void doesNotFire_atLunchTime() {
        Optional<IncidentDraft> result = rule.evaluate(makeLoginAt(14, 30), repository);

        assertFalse(result.isPresent());
    }

    @Test
    @DisplayName("НЕ срабатывает на границе: 07:00 — начало рабочего дня")
    void doesNotFire_atExactStartOfWorkHours() {
        Optional<IncidentDraft> result = rule.evaluate(makeLoginAt(7, 0), repository);

        assertFalse(result.isPresent(), "Login at 07:00 (exclusive end) must NOT trigger");
    }

    @Test
    @DisplayName("Игнорирует LOGIN_FAILURE — это не успешный вход, обрабатывается другим правилом")
    void ignores_loginFailure() {
        AuditEventCreated failure = makeEventAt("LOGIN_FAILURE", 23, 30);

        Optional<IncidentDraft> result = rule.evaluate(failure, repository);

        assertFalse(result.isPresent());
    }

    @Test
    @DisplayName("Описание содержит имя пользователя, час и IP")
    void incidentDescription_isMeaningful() {
        Optional<IncidentDraft> result = rule.evaluate(makeLoginAt(2, 14), repository);

        assertTrue(result.isPresent());
        String desc = result.get().description();
        assertTrue(desc.contains("alice"), "Description must contain username");
        assertTrue(desc.contains("02"), "Description must contain hour");
        assertTrue(desc.contains("10.0.0.1"), "Description must contain IP");
    }

    private AuditEventCreated makeLoginAt(int hour, int minute) {
        return makeEventAt("LOGIN_SUCCESS", hour, minute);
    }

    private AuditEventCreated makeEventAt(String action, int hour, int minute) {
        // Получаем фиксированное время сегодняшней даты с указанным часом
        var time = LocalDateTime.now()
                .withHour(hour).withMinute(minute).withSecond(0).withNano(0)
                .atZone(ZoneId.systemDefault())
                .toInstant();
        return new AuditEventCreated(
                UUID.randomUUID(),
                time,
                null, "alice",
                action,
                AuditCategory.AUTH,
                1, "SUCCESS",
                "User", null,
                "10.0.0.1", "test-agent",
                "Login attempt"
        );
    }
}