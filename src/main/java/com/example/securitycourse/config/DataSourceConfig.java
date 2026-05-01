package com.example.securitycourse.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import javax.sql.DataSource;

/**
 * Safety-net DataSource configuration.
 *
 * Sometimes resources are not copied to the runtime classpath (IDE run configs, etc.),
 * so application.properties is not picked up and Spring Boot fails with:
 * "Failed to configure a DataSource: 'url' attribute is not specified".
 *
 * This config creates the DataSource explicitly.
 * Values are taken from spring.datasource.* if present, otherwise from DB_* env vars.
 */
@Configuration
public class DataSourceConfig {

    private static final Logger log = LoggerFactory.getLogger(DataSourceConfig.class);

    @Bean
    @Primary
    public DataSource dataSource(Environment env) {
        String url = firstNonBlank(
                env.getProperty("spring.datasource.url"),
                env.getProperty("SPRING_DATASOURCE_URL"),
                env.getProperty("DB_URL")
        );
        String username = firstNonBlank(
                env.getProperty("spring.datasource.username"),
                env.getProperty("SPRING_DATASOURCE_USERNAME"),
                env.getProperty("DB_USERNAME")
        );
        String password = firstNonBlank(
                env.getProperty("spring.datasource.password"),
                env.getProperty("SPRING_DATASOURCE_PASSWORD"),
                env.getProperty("DB_PASSWORD")
        );

        if (!StringUtils.hasText(url)) {
            throw new IllegalStateException(
                    "Database URL is not configured. Set spring.datasource.url (or DB_URL env var)."
            );
        }

        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl(url);
        if (StringUtils.hasText(username)) cfg.setUsername(username);
        if (StringUtils.hasText(password)) cfg.setPassword(password);
        cfg.setDriverClassName("org.postgresql.Driver");

        // sensible defaults for a course project
        cfg.setMaximumPoolSize(10);
        cfg.setMinimumIdle(1);

        log.info("Configured DataSource (url={}, user={})", maskJdbcUrl(url), username);
        return new HikariDataSource(cfg);
    }

    private static String firstNonBlank(String... values) {
        if (values == null) return null;
        for (String v : values) {
            if (StringUtils.hasText(v)) return v;
        }
        return null;
    }

    private static String maskJdbcUrl(String url) {
        if (url == null) return null;
        return url.replaceAll("//[^/@:]+:[^/@]+@", "//***:***@");
    }
}
