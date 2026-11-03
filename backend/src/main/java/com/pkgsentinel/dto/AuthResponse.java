package com.pkgsentinel.dto;

public record AuthResponse(
    String token,
    UserSummary user,
    String message
) {}

