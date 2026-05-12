package com.example.securitycourse.controller.api;

import com.example.securitycourse.dto.AuthResponse;
import com.example.securitycourse.dto.LoginRequest;
import com.example.securitycourse.dto.RegisterRequest;
import com.example.securitycourse.dto.TwoFactorVerifyRequest;
import com.example.securitycourse.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthApiController {

    private final AuthService authService;

    public AuthApiController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest request, HttpServletRequest http) {
        authService.register(request, http);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
        try {
            return ResponseEntity.ok(authService.login(request, http));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/2fa/verify")
    public ResponseEntity<AuthResponse> verifyMfa(@Valid @RequestBody TwoFactorVerifyRequest req,
                                                  HttpServletRequest http) {
        try {
            return ResponseEntity.ok(authService.verifyMfa(req.getMfaToken(), req.getCode(), http));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}