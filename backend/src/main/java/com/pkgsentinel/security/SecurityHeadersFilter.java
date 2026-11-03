package com.pkgsentinel.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Filter that intercepts all HTTP responses to guarantee that WWW-Authenticate: Basic
 * is NEVER emitted to browsers or API clients, preventing Chrome native credential popups.
 * Also enforces baseline OWASP security headers.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityHeadersFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {

        if (response instanceof HttpServletResponse httpResponse) {
            HttpServletResponseWrapper responseWrapper = new SuppressBasicAuthResponseWrapper(httpResponse);

            // Set secure defense-in-depth headers
            httpResponse.setHeader("X-Content-Type-Options", "nosniff");
            httpResponse.setHeader("X-Frame-Options", "DENY");
            httpResponse.setHeader("X-XSS-Protection", "1; mode=block");
            httpResponse.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

            chain.doFilter(request, responseWrapper);
        } else {
            chain.doFilter(request, response);
        }
    }

    private static class SuppressBasicAuthResponseWrapper extends HttpServletResponseWrapper {

        public SuppressBasicAuthResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        @Override
        public void setHeader(String name, String value) {
            if ("WWW-Authenticate".equalsIgnoreCase(name) && value != null && value.toLowerCase().contains("basic")) {
                // Suppress HTTP Basic challenge and force Bearer challenge
                super.setHeader("WWW-Authenticate", "Bearer realm=\"PkgSentinel\"");
                return;
            }
            super.setHeader(name, value);
        }

        @Override
        public void addHeader(String name, String value) {
            if ("WWW-Authenticate".equalsIgnoreCase(name) && value != null && value.toLowerCase().contains("basic")) {
                super.setHeader("WWW-Authenticate", "Bearer realm=\"PkgSentinel\"");
                return;
            }
            super.addHeader(name, value);
        }
    }
}
