package com.pkgsentinel.controller;

import com.pkgsentinel.dto.HealthResponse;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class HealthController {

    private final JdbcTemplate jdbcTemplate;
    private final StringRedisTemplate redisTemplate;

    public HealthController(JdbcTemplate jdbcTemplate, StringRedisTemplate redisTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        this.redisTemplate = redisTemplate;
    }

    @GetMapping("/health")
    public ResponseEntity<HealthResponse> getHealth() {
        Map<String, String> components = new HashMap<>();

        // Check PostgreSQL
        try {
            jdbcTemplate.queryForObject("SELECT 1", Integer.class);
            components.put("database", "UP");
        } catch (Exception e) {
            components.put("database", "DOWN: " + e.getMessage());
        }

        // Check Redis
        try {
            redisTemplate.execute((RedisConnection connection) -> {
                connection.ping();
                return null;
            });
            components.put("redis", "UP");
        } catch (Exception e) {
            components.put("redis", "DOWN: " + e.getMessage());
        }

        boolean allHealthy = components.values().stream().allMatch("UP"::equals);
        String overallStatus = allHealthy ? "HEALTHY" : "DEGRADED";

        return ResponseEntity.ok(new HealthResponse(
            overallStatus,
            "pkgsentinel-backend",
            "0.1.0",
            Instant.now(),
            components
        ));
    }
}

