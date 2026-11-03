package com.pkgsentinel.service;

import com.pkgsentinel.dto.*;
import com.pkgsentinel.entity.UserEntity;
import com.pkgsentinel.entity.UserSessionEntity;
import com.pkgsentinel.repository.UserRepository;
import com.pkgsentinel.repository.UserSessionRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final UserSessionRepository userSessionRepository;
    private final PasswordHasher passwordHasher;
    private final SecureRandom secureRandom = new SecureRandom();

    public AuthService(
        UserRepository userRepository,
        UserSessionRepository userSessionRepository,
        PasswordHasher passwordHasher
    ) {
        this.userRepository = userRepository;
        this.userSessionRepository = userSessionRepository;
        this.passwordHasher = passwordHasher;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        String cleanUsername = request.username().trim().toLowerCase();
        String cleanEmail = request.email().trim().toLowerCase();

        if (userRepository.existsByUsername(cleanUsername)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username '" + cleanUsername + "' is already registered");
        }

        if (userRepository.existsByEmail(cleanEmail)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email '" + cleanEmail + "' is already registered");
        }

        String passwordHash = passwordHasher.hash(request.password());
        UserEntity user = new UserEntity(
            cleanUsername,
            cleanEmail,
            passwordHash,
            request.fullName().trim()
        );
        user = userRepository.save(user);

        String token = generateSecureToken();
        Instant expiresAt = Instant.now().plus(30, ChronoUnit.DAYS);
        UserSessionEntity session = new UserSessionEntity(token, user.getId(), expiresAt);
        userSessionRepository.save(session);

        UserSummary summary = toUserSummary(user);
        return new AuthResponse(token, summary, "Registration successful");
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        String identifier = request.usernameOrEmail().trim().toLowerCase();

        Optional<UserEntity> userOpt = identifier.contains("@")
            ? userRepository.findByEmail(identifier)
            : userRepository.findByUsername(identifier);

        if (userOpt.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password");
        }

        UserEntity user = userOpt.get();
        if (!passwordHasher.verify(request.password(), user.getPasswordHash())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password");
        }

        String token = generateSecureToken();
        Instant expiresAt = Instant.now().plus(30, ChronoUnit.DAYS);
        UserSessionEntity session = new UserSessionEntity(token, user.getId(), expiresAt);
        userSessionRepository.save(session);

        UserSummary summary = toUserSummary(user);
        return new AuthResponse(token, summary, "Login successful");
    }

    @Transactional(readOnly = true)
    public UserSummary getCurrentUser(String token) {
        if (token == null || token.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing authentication token");
        }

        String cleanToken = token.startsWith("Bearer ") ? token.substring(7).trim() : token.trim();
        UserSessionEntity session = userSessionRepository.findByToken(cleanToken)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Session invalid or expired"));

        if (session.isExpired()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Session expired");
        }

        UserEntity user = userRepository.findById(session.getUserId())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        return toUserSummary(user);
    }

    @Transactional
    public void logout(String token) {
        if (token != null && !token.isBlank()) {
            String cleanToken = token.startsWith("Bearer ") ? token.substring(7).trim() : token.trim();
            userSessionRepository.findById(cleanToken).ifPresent(userSessionRepository::delete);
        }
    }

    private UserSummary toUserSummary(UserEntity user) {
        return new UserSummary(
            user.getId(),
            user.getUsername(),
            user.getEmail(),
            user.getFullName(),
            user.getRole()
        );
    }

    private String generateSecureToken() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return "sentinel_sec_" + HexFormat.of().formatHex(randomBytes);
    }
}

