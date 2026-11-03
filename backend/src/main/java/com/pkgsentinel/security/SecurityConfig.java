package com.pkgsentinel.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public SecurityConfig(BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter) {
        this.bearerTokenAuthenticationFilter = bearerTokenAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(Customizer.withDefaults())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            
            // Explicitly disable HTTP Basic and Form Login to prevent browser credentials popups
            .httpBasic(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)

            // Custom AuthenticationEntryPoint that returns RFC 6750 Bearer challenge (never Basic)
            .exceptionHandling(ex -> ex.authenticationEntryPoint(customAuthenticationEntryPoint()))

            .authorizeHttpRequests(auth -> auth
                // 1. Public Authentication Endpoints (CRITICAL: NEVER require existing token)
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/register", "/api/v1/auth/login").permitAll()
                
                // 2. Public Health & Monitoring
                .requestMatchers("/api/v1/health", "/api/v1/health/**").permitAll()
                
                // 3. Internal Security Engine Worker Callbacks (authenticated via internal token)
                .requestMatchers("/internal/v1/**").permitAll()

                // 4. Scan endpoints (Guest scans permitted; owner-specific authorization enforced in controller)
                .requestMatchers(HttpMethod.GET, "/api/v1/scans", "/api/v1/scans/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/scans").permitAll()

                // 5. Protected Profile and Logout Endpoints
                .requestMatchers("/api/v1/auth/me", "/api/v1/auth/logout").authenticated()

                // 6. All other requests require authentication
                .anyRequest().authenticated()
            )

            .addFilterBefore(bearerTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationEntryPoint customAuthenticationEntryPoint() {
        return (request, response, authException) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            // RFC 6750: Use Bearer realm instead of Basic realm
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"PkgSentinel\", error=\"invalid_token\"");

            Map<String, Object> errorBody = new HashMap<>();
            errorBody.put("timestamp", Instant.now().toString());
            errorBody.put("status", HttpServletResponse.SC_UNAUTHORIZED);
            errorBody.put("error", "Unauthorized");
            errorBody.put("message", "Authentication required. Please sign in with valid credentials.");
            errorBody.put("path", request.getRequestURI());

            response.getWriter().write(objectMapper.writeValueAsString(errorBody));
        };
    }
}

