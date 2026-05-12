package com.example.securitycourse.service;

import com.example.securitycourse.audit.AuditCategory;
import com.example.securitycourse.domain.AuditLog;
import com.example.securitycourse.repository.AuditLogRepository;
import com.example.securitycourse.service.HashChainService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * Unit-тесты HashChainService — ядра tamper-evident журнала.
 * Проверяют: канонизацию записей, SHA-256, монотонный timestamp,
 * корректную валидацию цепочки и детекцию подделки.
 *
 * Закрывает требование OWASP A08 (Software and Data Integrity Failures).
 */
@DisplayName("HashChainService — целостность журнала аудита")
class HashChainServiceTest {

    private HashChainService service;
    private AuditLogRepository auditLogRepository;

    @BeforeEach
    void setUp() {
        auditLogRepository = Mockito.mock(AuditLogRepository.class);
        service = new HashChainService(auditLogRepository);
        ReflectionTestUtils.setField(service, "genesis", "GENESIS");
    }

    @Test
    @DisplayName("SHA-256 даёт ожидаемый хеш для известного входа")
    void sha256_knownVector() {
        // Известный тестовый вектор: SHA-256("abc") = ba7816bf...
        String hash = service.sha256Hex("abc");
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hash);
    }

    @Test
    @DisplayName("Канонизация записи стабильна при одинаковом контенте")
    void canonicalize_stable() {
        AuditLog log1 = makeLog("alice", "LOGIN_SUCCESS", "SUCCESS", 1, "10.0.0.1");
        AuditLog log2 = makeLog("alice", "LOGIN_SUCCESS", "SUCCESS", 1, "10.0.0.1");
        // Одинаковый timestamp нужен — копируем
        log2.setTimestamp(log1.getTimestamp());

        assertEquals(service.canonicalize(log1), service.canonicalize(log2),
                "Same input must produce identical canonical form");
    }

    @Test
    @DisplayName("Изменение любого поля → другая каноническая форма")
    void canonicalize_sensitiveToAllFields() {
        AuditLog original = makeLog("alice", "LOGIN_SUCCESS", "SUCCESS", 1, "10.0.0.1");
        String origCanon = service.canonicalize(original);

        AuditLog changedUser = makeLog("bob", "LOGIN_SUCCESS", "SUCCESS", 1, "10.0.0.1");
        changedUser.setTimestamp(original.getTimestamp());
        assertNotEquals(origCanon, service.canonicalize(changedUser));

        AuditLog changedIp = makeLog("alice", "LOGIN_SUCCESS", "SUCCESS", 1, "10.0.0.2");
        changedIp.setTimestamp(original.getTimestamp());
        assertNotEquals(origCanon, service.canonicalize(changedIp));

        AuditLog changedAction = makeLog("alice", "LOGIN_FAILURE", "SUCCESS", 1, "10.0.0.1");
        changedAction.setTimestamp(original.getTimestamp());
        assertNotEquals(origCanon, service.canonicalize(changedAction));
    }

    @Test
    @DisplayName("nextMonotonicTimestamp возвращает строго возрастающие значения")
    void timestamp_strictlyMonotonic() {
        Instant t1 = service.nextMonotonicTimestamp();
        Instant t2 = service.nextMonotonicTimestamp();
        Instant t3 = service.nextMonotonicTimestamp();

        assertTrue(t2.isAfter(t1), "t2 must be after t1");
        assertTrue(t3.isAfter(t2), "t3 must be after t2");
    }

    @Test
    @DisplayName("Целая цепочка из 3 правильно построенных записей валидна")
    void verifyChain_validChain() {
        List<AuditLog> chain = buildValidChain(3);
        when(auditLogRepository.findAllOrderedBySeq()).thenReturn(chain);

        HashChainService.IntegrityCheckResult result = service.verifyChain();

        assertTrue(result.valid(), "Valid chain must pass verification, got: " + result.message());
        assertEquals(3, result.recordsChecked());
        assertNull(result.firstFailureId());
    }

    @Test
    @DisplayName("Пустая цепочка валидна (нет записей — нечего проверять)")
    void verifyChain_emptyChainIsValid() {
        when(auditLogRepository.findAllOrderedBySeq()).thenReturn(List.of());

        HashChainService.IntegrityCheckResult result = service.verifyChain();

        assertTrue(result.valid());
        assertEquals(0, result.recordsChecked());
    }

    @Test
    @DisplayName("Tamper-detection: изменение details в средней записи обнаруживается")
    void verifyChain_detectsTamperingInMiddleRecord() {
        List<AuditLog> chain = buildValidChain(5);

        // Подделываем 3-ю запись — меняем details, не пересчитывая hash
        // (имитация прямой UPDATE в БД через pgAdmin)
        chain.get(2).setDetails("TAMPERED BY ATTACKER");

        when(auditLogRepository.findAllOrderedBySeq()).thenReturn(chain);

        HashChainService.IntegrityCheckResult result = service.verifyChain();

        assertFalse(result.valid(), "Tampering must be detected");
        assertNotNull(result.firstFailureId(), "Failure ID must be reported");
        assertEquals(chain.get(2).getId().toString(), result.firstFailureId(),
                "First failure must point to the tampered record");
    }

    @Test
    @DisplayName("Tamper-detection: удаление записи (разрыв prev_hash) обнаруживается")
    void verifyChain_detectsDeletedRecord() {
        List<AuditLog> chain = buildValidChain(5);

        // Удаляем 3-ю запись из цепочки — теперь 4-я запись ссылается на хеш которого нет
        chain.remove(2);

        when(auditLogRepository.findAllOrderedBySeq()).thenReturn(chain);

        HashChainService.IntegrityCheckResult result = service.verifyChain();

        assertFalse(result.valid(), "Missing record in chain must be detected");
    }

    @Test
    @DisplayName("Tamper-detection: подделанный prev_hash обнаруживается")
    void verifyChain_detectsForgedPrevHash() {
        List<AuditLog> chain = buildValidChain(3);

        // Меняем prev_hash в средней записи на произвольное значение
        chain.get(1).setPrevHash("0000000000000000000000000000000000000000000000000000000000000000");

        when(auditLogRepository.findAllOrderedBySeq()).thenReturn(chain);

        HashChainService.IntegrityCheckResult result = service.verifyChain();

        assertFalse(result.valid());
        assertEquals(chain.get(1).getId().toString(), result.firstFailureId());
    }

    // ===== Вспомогательные методы =====

    private AuditLog makeLog(String username, String action, String result, int severity, String ip) {
        AuditLog l = new AuditLog();
        l.setId(UUID.randomUUID());
        l.setActorUsername(username);
        l.setAction(action);
        l.setResult(result);
        l.setSeverity(severity);
        l.setCategory(AuditCategory.AUTH);
        l.setIp(ip);
        l.setDetails("Test event");
        l.setTimestamp(Instant.now().truncatedTo(ChronoUnit.MICROS));
        return l;
    }

    /** Строит правильно подписанную цепочку из N записей. */
    private List<AuditLog> buildValidChain(int n) {
        AuditLog[] arr = new AuditLog[n];
        String prevHash = "GENESIS";
        Instant ts = Instant.now().truncatedTo(ChronoUnit.MICROS);

        for (int i = 0; i < n; i++) {
            AuditLog l = makeLog("user" + i, "LOGIN_SUCCESS", "SUCCESS", 1, "10.0.0." + (i + 1));
            l.setTimestamp(ts.plusSeconds(i));
            l.setPrevHash(prevHash);

            String content = service.canonicalize(l);
            String hash = service.sha256Hex(prevHash + "|" + content);
            l.setHash(hash);

            arr[i] = l;
            prevHash = hash;
        }
        return new java.util.ArrayList<>(Arrays.asList(arr));
    
    }
}