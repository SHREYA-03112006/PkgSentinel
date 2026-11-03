package com.pkgsentinel.repository;

import com.pkgsentinel.entity.ScanJobEntity;
import com.pkgsentinel.entity.enums.Ecosystem;
import com.pkgsentinel.entity.enums.ScanStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ScanJobRepository extends JpaRepository<ScanJobEntity, UUID> {
    Optional<ScanJobEntity> findFirstByEcosystemAndPackageNameAndVersionOrderByCreatedAtDesc(
        Ecosystem ecosystem, String packageName, String version
    );
    List<ScanJobEntity> findByStatus(ScanStatus status);
    Page<ScanJobEntity> findAllByOrderByCreatedAtDesc(Pageable pageable);
}

