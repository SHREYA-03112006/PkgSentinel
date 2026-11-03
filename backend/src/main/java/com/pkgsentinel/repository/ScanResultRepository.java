package com.pkgsentinel.repository;

import com.pkgsentinel.entity.ScanResultEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ScanResultRepository extends JpaRepository<ScanResultEntity, UUID> {
    Optional<ScanResultEntity> findByScanJobId(UUID scanJobId);
}

