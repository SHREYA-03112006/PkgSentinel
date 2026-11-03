package com.pkgsentinel.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "package_versions", uniqueConstraints = {
    @UniqueConstraint(name = "uq_package_version", columnNames = {"package_id", "version_string"})
})
public class PackageVersionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "package_id", nullable = false)
    private PackageEntity packageEntity;

    @Column(name = "version_string", nullable = false, length = 128)
    private String versionString;

    @Column(name = "sha256_hash", length = 64)
    private String sha256Hash;

    @Column(name = "tarball_url", columnDefinition = "TEXT")
    private String tarballUrl;

    @Column(name = "release_date")
    private Instant releaseDate;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public PackageVersionEntity() {}

    public PackageVersionEntity(PackageEntity packageEntity, String versionString) {
        this.packageEntity = packageEntity;
        this.versionString = versionString;
        this.createdAt = Instant.now();
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public PackageEntity getPackageEntity() { return packageEntity; }
    public void setPackageEntity(PackageEntity packageEntity) { this.packageEntity = packageEntity; }

    public String getVersionString() { return versionString; }
    public void setVersionString(String versionString) { this.versionString = versionString; }

    public String getSha256Hash() { return sha256Hash; }
    public void setSha256Hash(String sha256Hash) { this.sha256Hash = sha256Hash; }

    public String getTarballUrl() { return tarballUrl; }
    public void setTarballUrl(String tarballUrl) { this.tarballUrl = tarballUrl; }

    public Instant getReleaseDate() { return releaseDate; }
    public void setReleaseDate(Instant releaseDate) { this.releaseDate = releaseDate; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
