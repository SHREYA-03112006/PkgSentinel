package com.pkgsentinel.repository;

import com.pkgsentinel.entity.UserSessionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSessionEntity, String> {
    Optional<UserSessionEntity> findByToken(String token);
    void deleteByUserId(UUID userId);
}

