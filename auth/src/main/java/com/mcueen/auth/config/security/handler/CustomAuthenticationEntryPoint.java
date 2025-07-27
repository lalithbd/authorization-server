package com.mcueen.auth.config.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.config.security.model.UnAuthorizedResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        UnAuthorizedResponse authorizedResponse = UnAuthorizedResponse.builder()
                .status(String.valueOf(HttpStatus.UNAUTHORIZED.value()))
                .message("Invalid authorization").build();
        response.getOutputStream().write(objectMapper.writeValueAsString(authorizedResponse).getBytes(StandardCharsets.UTF_8));
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
    }
}
