package com.pkgsentinel.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    public record ErrorResponse(
        Instant timestamp,
        int status,
        String error,
        String message,
        String path,
        Map<String, String> validationErrors
    ) {
        public ErrorResponse(int status, String error, String message, String path) {
            this(Instant.now(), status, error, message, path, null);
        }

        public ErrorResponse(int status, String error, String message, String path, Map<String, String> validationErrors) {
            this(Instant.now(), status, error, message, path, validationErrors);
        }
    }

    /**
     * Handles explicit ResponseStatusException (401, 403, 404, 409, etc.).
     * CRITICAL: Ensures WWW-Authenticate: Basic is NEVER emitted so Chrome never triggers
     * its native credential dialog. If 401, uses RFC 6750 Bearer authentication realm.
     */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ErrorResponse> handleResponseStatusException(
        ResponseStatusException ex,
        HttpServletRequest request,
        HttpServletResponse response
    ) {
        HttpStatus status = HttpStatus.valueOf(ex.getStatusCode().value());
        String reason = ex.getReason() != null ? ex.getReason() : status.getReasonPhrase();

        HttpHeaders headers = new HttpHeaders();
        if (status == HttpStatus.UNAUTHORIZED) {
            // Explicitly set Bearer realm and prevent any fallback to Basic
            headers.set(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"PkgSentinel\", error=\"invalid_token\"");
        }

        ErrorResponse body = new ErrorResponse(
            status.value(),
            status.getReasonPhrase(),
            reason,
            request.getRequestURI()
        );

        return new ResponseEntity<>(body, headers, status);
    }

    /**
     * Handles Bean Validation failures (e.g. invalid email, short password, empty fields).
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(
        MethodArgumentNotValidException ex,
        HttpServletRequest request
    ) {
        Map<String, String> fieldErrors = new HashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(fe.getField(), fe.getDefaultMessage());
        }

        ErrorResponse body = new ErrorResponse(
            HttpStatus.BAD_REQUEST.value(),
            "Bad Request",
            "Request validation failed",
            request.getRequestURI(),
            fieldErrors
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    /**
     * Handles access denial / authorization rejections.
     */
    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<ErrorResponse> handleSecurityException(
        SecurityException ex,
        HttpServletRequest request
    ) {
        ErrorResponse body = new ErrorResponse(
            HttpStatus.FORBIDDEN.value(),
            "Forbidden",
            ex.getMessage() != null ? ex.getMessage() : "Access denied",
            request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }

    /**
     * Handles invalid client arguments.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(
        IllegalArgumentException ex,
        HttpServletRequest request
    ) {
        ErrorResponse body = new ErrorResponse(
            HttpStatus.BAD_REQUEST.value(),
            "Bad Request",
            ex.getMessage() != null ? ex.getMessage() : "Invalid argument",
            request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    /**
     * Fallback for unhandled unexpected exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnhandledException(
        Exception ex,
        HttpServletRequest request
    ) {
        log.error("Unhandled internal server error on {}: {}", request.getRequestURI(), ex.getMessage(), ex);

        ErrorResponse body = new ErrorResponse(
            HttpStatus.INTERNAL_SERVER_ERROR.value(),
            "Internal Server Error",
            "An unexpected server error occurred. Please contact security operations.",
            request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}
