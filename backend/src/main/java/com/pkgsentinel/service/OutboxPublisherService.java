package com.pkgsentinel.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pkgsentinel.entity.OutboxEventEntity;
import com.pkgsentinel.repository.OutboxEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.stream.RecordId;
import org.springframework.data.redis.connection.stream.StreamRecords;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Service
public class OutboxPublisherService {

    private static final Logger log = LoggerFactory.getLogger(OutboxPublisherService.class);
    private static final String SCAN_STREAM_KEY = "stream:scan-jobs";

    private final OutboxEventRepository outboxEventRepository;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public OutboxPublisherService(
        OutboxEventRepository outboxEventRepository,
        StringRedisTemplate redisTemplate
    ) {
        this.outboxEventRepository = outboxEventRepository;
        this.redisTemplate = redisTemplate;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Polls unpublished outbox events and publishes them to Redis Streams.
     * Retries automatically if Redis is temporarily unavailable.
     */
    @Scheduled(fixedDelayString = "${pkgsentinel.outbox.poll-interval-ms:2000}")
    @Transactional
    public void processPendingOutboxEvents() {
        List<OutboxEventEntity> pendingEvents = outboxEventRepository.findPendingEvents();
        if (pendingEvents.isEmpty()) {
            return;
        }

        log.debug("Found {} pending outbox event(s) to publish", pendingEvents.size());
        for (OutboxEventEntity event : pendingEvents) {
            publishEvent(event);
        }
    }

    public boolean publishEvent(OutboxEventEntity event) {
        try {
            Map<String, String> payloadMap = objectMapper.readValue(
                event.getPayload(),
                new TypeReference<Map<String, String>>() {}
            );

            RecordId recordId = redisTemplate.opsForStream().add(
                StreamRecords.newRecord().ofStrings(payloadMap).withStreamKey(SCAN_STREAM_KEY)
            );

            event.setPublished(true);
            event.setPublishedAt(Instant.now());
            event.setLastError(null);
            outboxEventRepository.save(event);

            log.info("Published outbox event {} (Job {}) to stream {} with recordId {}",
                event.getId(), event.getAggregateId(), SCAN_STREAM_KEY, recordId);
            return true;
        } catch (Exception e) {
            log.warn("Failed to publish outbox event {} to Redis stream: {}", event.getId(), e.getMessage());
            event.setRetryCount(event.getRetryCount() + 1);
            event.setLastError(e.getMessage());
            outboxEventRepository.save(event);
            return false;
        }
    }
}
