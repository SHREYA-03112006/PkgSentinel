package com.pkgsentinel.repository;

import com.pkgsentinel.entity.PackageEntity;
import com.pkgsentinel.entity.enums.Ecosystem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface PackageRepository extends JpaRepository<PackageEntity, UUID> {
    Optional<PackageEntity> findByEcosystemAndName(Ecosystem ecosystem, String name);
}
