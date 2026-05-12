package com.example.securitycourse.service;

import com.example.securitycourse.domain.AuditLog;
import com.example.securitycourse.repository.AuditLogRepository;
import jakarta.annotation.PostConstruct;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Hash chain поверх журнала аудита (tamper-evident log).
 * Каждая запись содержит SHA-256(prev_hash || canonical_content).
 *
 * Для синхронизации используется row-level lock на единственной строке таблицы
 * audit_chain_state (SELECT ... FOR UPDATE), что гарантирует строгую упорядоченность
 * вставок даже при параллельных транзакциях.
 *
 * Дополнительно сервис гарантирует монотонно растущий timestamp записей через
 * nextMonotonicTimestamp() — это нужно для корректной сортировки записей при verifyChain
 * даже если две транзакции (например, основной поток и @Async-корреляция) запросили
 * Instant.now() в одной микросекунде.
 *
 * Закрывает требование OWASP A08 (Software and Data Integrity Failures) и
 * A09 (Security Logging and Monitoring Failures).
 */
@Service
public class HashChainService {

    private static final Logger log = LoggerFactory.getLogger(HashChainService.class);

    @PersistenceContext
    private EntityManager em;

    private final AuditLogRepository auditLogRepository;

    @Value("${app.audit.hash-chain.genesis:GENESIS}")
    private String genesis;

    /** Последний выданный timestamp — используется для гарантии монотонности. */
    private final AtomicReference<Instant> lastTimestamp = new AtomicReference<>(Instant.EPOCH);

    public HashChainService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    /** При старте подтягиваем максимальный ts из БД, чтобы новые записи продолжали последовательность. */
    @PostConstruct
    public void initLastTimestamp() {
        try {
            Object result = em.createNativeQuery("SELECT MAX(ts) FROM audit_log").getSingleResult();
            if (result instanceof Instant i) {
                lastTimestamp.set(i.truncatedTo(ChronoUnit.MICROS));
                log.info("HashChainService: initialized lastTimestamp from DB = {}", i);
            } else if (result != null) {
                // PostgreSQL может вернуть OffsetDateTime или Timestamp в зависимости от версии драйвера
                Instant parsed = Instant.parse(result.toString().replace(" ", "T"));
                lastTimestamp.set(parsed.truncatedTo(ChronoUnit.MICROS));
            }
        } catch (Exception e) {
            log.info("HashChainService: no previous audit records, starting fresh");
        }
    }

    /**
     * Возвращает следующий timestamp с гарантией строгой монотонности.
     * Если Instant.now() меньше или равен последнему выданному — добавляем 1 микросекунду.
     * Используется внутри глобального lock (после acquirePreviousHash) — поэтому потокобезопасно
     * относительно записи в журнал.
     */
    public Instant nextMonotonicTimestamp() {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        return lastTimestamp.updateAndGet(prev ->
                now.isAfter(prev) ? now : prev.plus(1, ChronoUnit.MICROS)
        );
    }

    /**
     * Получает предыдущий хеш с блокировкой строки-сентинеля.
     * Должен вызываться внутри транзакции.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public String acquirePreviousHash() {
        Object[] row = (Object[]) em.createNativeQuery(
                "SELECT last_hash, last_seq FROM audit_chain_state WHERE id = 1 FOR UPDATE")
                .getSingleResult();
        return row[0] == null ? genesis : row[0].toString();
    }

    /** Обновляет состояние сентинеля после записи нового лога. */
    @Transactional(propagation = Propagation.REQUIRED)
    public void updateChainState(String newHash) {
        em.createNativeQuery(
                "UPDATE audit_chain_state SET last_hash = ?, last_seq = last_seq + 1, updated_at = now() WHERE id = 1")
                .setParameter(1, newHash)
                .executeUpdate();
    }

    /**
     * Каноническая сериализация записи для хеширования.
     * Изменение любого поля → изменение хеша → разрыв цепочки.
     */
    public String canonicalize(AuditLog l) {
        return String.join("|",
                String.valueOf(l.getTimestamp()),
                nz(l.getActorUsername()),
                nz(l.getAction()),
                nz(l.getResult()),
                String.valueOf(l.getSeverity()),
                nz(l.getCategory() == null ? null : l.getCategory().name()),
                nz(l.getEntityType()),
                nz(l.getEntityId()),
                nz(l.getIp()),
                nz(l.getDetails())
        );
    }

    public String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * Полная проверка целостности цепочки.
     * Возвращает количество проверенных записей и идентификатор первой повреждённой (или null).
     */
    @Transactional(readOnly = true)
    public IntegrityCheckResult verifyChain() {
        List<AuditLog> all = auditLogRepository.findAllOrderedBySeq();
        String expectedPrev = genesis;
        int checked = 0;
        for (AuditLog l : all) {
            checked++;
            // 1. Проверяем prev_hash — должен совпадать с хешем предыдущего звена
            if (!expectedPrev.equals(nz(l.getPrevHash()))) {
                log.warn("Chain break at seq={} id={}: expected prev={}, actual prev={}",
                        l.getSeq(), l.getId(), expectedPrev, l.getPrevHash());
                return new IntegrityCheckResult(checked, false, l.getId().toString(),
                        "prev_hash mismatch (запись изменена или пропущена)");
            }
            // 2. Пересчитываем hash и сверяем
            String content = canonicalize(l);
            String recomputed = sha256Hex(expectedPrev + "|" + content);
            if (!recomputed.equals(nz(l.getHash()))) {
                log.warn("Chain hash mismatch at seq={} id={}", l.getSeq(), l.getId());
                return new IntegrityCheckResult(checked, false, l.getId().toString(),
                        "hash mismatch (содержимое записи изменено)");
            }
            expectedPrev = l.getHash();
        }
        return new IntegrityCheckResult(checked, true, null, "OK");
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    public record IntegrityCheckResult(int recordsChecked, boolean valid, String firstFailureId, String message) {
    }
}