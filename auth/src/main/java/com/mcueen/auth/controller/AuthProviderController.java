package com.mcueen.auth.controller;

import com.mcueen.auth.controller.dto.AuthProviderDto;
import com.mcueen.auth.service.AuthProviderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/auth")
public class AuthProviderController {

    @Autowired
    private AuthProviderService authProviderService;

    @GetMapping("/providers")
    public ResponseEntity<List<AuthProviderDto>> getProviders() {
        return ResponseEntity.ok(authProviderService.getEnabledProviders());
    }
}
