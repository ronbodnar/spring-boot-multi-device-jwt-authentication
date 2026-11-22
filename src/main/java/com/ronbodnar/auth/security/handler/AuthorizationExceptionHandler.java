package com.ronbodnar.auth.security.handler;

import com.ronbodnar.auth.exception.ErrorCode;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;

import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
public class AuthorizationExceptionHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        log.info("Authorization error: {}", accessDeniedException.getMessage());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        final Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("timestamp", Instant.now().toString());
        body.put("path", request.getRequestURI());
        body.put("code", ErrorCode.NOT_AUTHORIZED);

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);

    }
}