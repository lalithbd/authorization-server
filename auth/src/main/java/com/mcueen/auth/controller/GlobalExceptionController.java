package com.mcueen.auth.controller;

import com.mcueen.auth.exception.AuthServiceException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionController {

    @ExceptionHandler(value = AuthServiceException.class)
    public ResponseEntity<?> handleAuthServiceException(AuthServiceException authServiceException) {
        return new ResponseEntity<>(authServiceException.getMessage(), authServiceException.getHttpStatus());
    }
}
