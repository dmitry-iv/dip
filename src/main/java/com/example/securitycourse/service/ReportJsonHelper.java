package com.example.securitycourse.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Хелпер для сериализации данных графиков в JSON прямо из Thymeleaf.
 * Используется чтобы передать массивы в JS на странице без проблем
 * с экранированием ", ', \n внутри th:inline.
 */
@Component("reportJsonHelper")
public class ReportJsonHelper {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /** Формирует JSON {labels: [...], audit: [...], incidents: [...]} для дашборда. */
    public String toJson(List<String> labels, long[] audit, long[] incidents) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("labels", labels == null ? List.of() : labels);
        map.put("audit", audit == null ? new long[0] : audit);
        map.put("incidents", incidents == null ? new long[0] : incidents);
        try {
            return objectMapper.writeValueAsString(map);
        } catch (Exception e) {
            return "{\"labels\":[],\"audit\":[],\"incidents\":[]}";
        }
    }

    /** Формирует JSON {labels:[...], values:[...]} для одиночного pie/bar чарта. */
    public String toJsonPair(List<String> labels, List<Long> values) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("labels", labels == null ? List.of() : labels);
        map.put("values", values == null ? List.of() : values);
        try {
            return objectMapper.writeValueAsString(map);
        } catch (Exception e) {
            return "{\"labels\":[],\"values\":[]}";
        }
    }

    /** Сериализует произвольный объект (LongArray тоже понимает). */
    public String anyToJson(Object o) {
        if (o == null) return "null";
        try {
            return objectMapper.writeValueAsString(o);
        } catch (Exception e) {
            return "null";
        }
    }
}