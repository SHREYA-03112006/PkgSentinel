package com.pkgsentinel.entity;

import com.pkgsentinel.entity.enums.Ecosystem;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "packages", uniqueConstraints = {
    @UniqueConstraint(name = "uq_packages_ecosystem_name", columnNames = {"ecosystem", "name"})
})
public class PackageEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private Ecosystem ecosystem;

    @Column(nullable = false)
    private String name;

    @Column(name = "is_quarantined", nullable = false)
    private boolean quarantined = false;

    @Column(name = "first_seen_at", nullable = false, updatable = false)
    private Instant firstSeenAt = Instant.now();

    @Column(name = "last_analyzed_at")
    private Instant lastAnalyzedAt;

    public PackageEntity() {}

    public PackageEntity(Ecosystem ecosystem, String name) {
        this.ecosystem = ecosystem;
        this.name = name;
        this.firstSeenAt = Instant.now();
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public Ecosystem getEcosystem() { return ecosystem; }
    public void setEcosystem(Ecosystem ecosystem) { this.ecosystem = ecosystem; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public boolean isQuarantined() { return quarantined; }
    public void setQuarantined(boolean quarantined) { this.quarantined = quarantined; }

    public Instant getFirstSeenAt() { return firstSeenAt; }
    public void setFirstSeenAt(Instant firstSeenAt) { this.firstSeenAt = firstSeenAt; }

    public Instant getLastAnalyzedAt() { return lastAnalyzedAt; }
    public void setLastAnalyzedAt(Instant lastAnalyzedAt) { this.lastAnalyzedAt = lastAnalyzedAt; }
}

