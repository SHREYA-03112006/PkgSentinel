package com.pkgsentinel.security;

import com.pkgsentinel.dto.UserSummary;
import com.pkgsentinel.entity.UserEntity;
import com.pkgsentinel.entity.UserSessionEntity;
import com.pkgsentinel.repository.UserRepository;
import com.pkgsentinel.repository.UserSessionRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Filter that extracts and verifies Bearer tokens from the Authorization header.
 * CRITICAL RULE: This filter NEVER rejects requests to public endpoints (registration,
 * login, health) when an Authorization header is absent or invalid.
 */
@Component
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

    private final UserSessionRepository userSessionRepository;
    private final UserRepository userRepository;

    public BearerTokenAuthenticationFilter(
        UserSessionRepository userSessionRepository,
        UserRepository userRepository
    ) {
        this.userSessionRepository = userSessionRepository;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {

        String path = request.getRequestURI();

        // 1. Skip token authentication entirely on public authentication and health paths
        if (isPublicEndpoint(path, request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Extract Bearer token if present
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7).trim();
            if (!token.isEmpty()) {
                authenticateSessionToken(token);
            }
        }

        filterChain.doFilter(request, response);
    }

    private void authenticateSessionToken(String token) {
        Optional<UserSessionEntity> sessionOpt = userSessionRepository.findByToken(token);
        if (sessionOpt.isEmpty()) {
            return; // Invalid token; leave SecurityContext empty for entry point to handle
        }

        UserSessionEntity session = sessionOpt.get();
        if (session.isExpired()) {
            return; // Expired token
        }

        Optional<UserEntity> userOpt = userRepository.findById(session.getUserId());
        if (userOpt.isEmpty()) {
            return;
        }

        UserEntity user = userOpt.get();
        UserSummary summary = new UserSummary(
            user.getId(),
            user.getUsername(),
            user.getEmail(),
            user.getFullName(),
            user.getRole()
        );

        List<SimpleGrantedAuthority> authorities = Collections.singletonList(
            new SimpleGrantedAuthority("ROLE_" + user.getRole().toUpperCase())
        );

        UsernamePasswordAuthenticationToken authentication =
            new UsernamePasswordAuthenticationToken(summary, null, authorities);

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private boolean isPublicEndpoint(String path, String method) {
        if ("POST".equalsIgnoreCase(method)) {
            if (path.endsWith("/api/v1/auth/register") || path.endsWith("/auth/register")) return true;
            if (path.endsWith("/api/v1/auth/login") || path.endsWith("/auth/login")) return true;
        }
        if (path.contains("/api/v1/health") || path.contains("/health")) return true;
        if (path.contains("/internal/v1/")) return true;
        return false;
    }
}

