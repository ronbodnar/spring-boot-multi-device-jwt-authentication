package com.ronbodnar.auth.security.handler;

import com.ronbodnar.auth.exception.ErrorCode;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;

import org.jspecify.annotations.NonNull;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
public class AuthenticationExceptionHandler implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, @NonNull AuthenticationException authException) throws IOException {
        log.warn("Unauthorized request to {} from {}", request.getRequestURI(), request.getRemoteAddr());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        final Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("timestamp", Instant.now().toString());
        body.put("path", request.getRequestURI());
        body.put("code", ErrorCode.INVALID_ACCESS_TOKEN);

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }

}