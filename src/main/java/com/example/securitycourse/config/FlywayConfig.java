package com.example.securitycourse.config;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.exception.FlywayValidateException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import javax.sql.DataSource;

/**
 * Ensures Flyway runs BEFORE JPA initializes.
 *
 * We intentionally avoid Spring Boot Flyway autoconfigure types (like FlywayMigrationStrategy)
 * because their package/class names can differ across Spring Boot 4 builds and setups.
 * This config depends only on Flyway core + DataSource.
 */
@Configuration
public class FlywayConfig {

    private static final Logger log = LoggerFactory.getLogger(FlywayConfig.class);

    /**
     * Run Flyway early (before EntityManagerFactory creation).
     *
     * Dev-friendly behavior:
     * - If validation fails due to checksum mismatch and app.flyway.auto-repair=true (default),
     *   we run flyway.repair() and then migrate.
     */
    @Bean
    public static BeanFactoryPostProcessor flywayBeforeJpa(Environment env) {
        return (ConfigurableListableBeanFactory beanFactory) -> {
            DataSource dataSource = beanFactory.getBean(DataSource.class);

            boolean autoRepair = env.getProperty("app.flyway.auto-repair", Boolean.class, true);
            boolean baselineOnMigrate = env.getProperty("spring.flyway.baseline-on-migrate", Boolean.class, false);
            String locationsProp = env.getProperty("spring.flyway.locations", "classpath:db/migration");
            String[] locations = locationsProp.split("\\s*,\\s*");

            Flyway flyway = Flyway.configure()
                    .dataSource(dataSource)
                    .baselineOnMigrate(baselineOnMigrate)
                    .locations(locations)
                    .load();

            try {
                flyway.validate();
            } catch (FlywayValidateException ex) {
                if (!autoRepair) {
                    throw ex;
                }
                log.warn("Flyway validation failed. Running repair() and continuing (dev-friendly). Cause: {}", ex.getMessage());
                flyway.repair();
            }

            log.info("Running Flyway migrations (early trigger before JPA)...");
            flyway.migrate();
        };
    }
}
