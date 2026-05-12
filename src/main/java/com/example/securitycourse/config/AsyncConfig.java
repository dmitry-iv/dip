package com.example.securitycourse.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

/**
 * Асинхронное исполнение для:
 *  - корреляционного движка (анализ событий не должен блокировать запросы)
 *  - сервиса алертов (отправка email тоже асинхронна)
 *
 * Два отдельных пула — чтобы зависший SMTP не блокировал корреляцию и наоборот.
 */
@Configuration
@EnableAsync
public class AsyncConfig {

    @Bean(name = "correlationExecutor")
    public Executor correlationExecutor() {
        ThreadPoolTaskExecutor ex = new ThreadPoolTaskExecutor();
        ex.setCorePoolSize(2);
        ex.setMaxPoolSize(4);
        ex.setQueueCapacity(500);
        ex.setThreadNamePrefix("corr-");
        ex.setWaitForTasksToCompleteOnShutdown(true);
        ex.setAwaitTerminationSeconds(10);
        ex.initialize();
        return ex;
    }

    @Bean(name = "alertExecutor")
    public Executor alertExecutor() {
        ThreadPoolTaskExecutor ex = new ThreadPoolTaskExecutor();
        ex.setCorePoolSize(1);
        ex.setMaxPoolSize(2);
        ex.setQueueCapacity(200);
        ex.setThreadNamePrefix("alert-");
        ex.setWaitForTasksToCompleteOnShutdown(true);
        ex.setAwaitTerminationSeconds(15);
        ex.initialize();
        return ex;
    }
}