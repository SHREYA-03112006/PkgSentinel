package com.pkgsentinel.repository;

import com.pkgsentinel.entity.PackageVersionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface PackageVersionRepository extends JpaRepository<PackageVersionEntity, UUID> {
    Optional<PackageVersionEntity> findByPackageEntityIdAndVersionString(UUID packageId, String versionString);
    Optional<PackageVersionEntity> findBySha256Hash(String sha256Hash);
}
