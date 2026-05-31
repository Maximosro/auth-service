package com.sro.authservice.controller;

import com.sro.authservice.dto.AuthResponse;
import com.sro.authservice.dto.LoginRequest;
import com.sro.authservice.dto.RegisterRequest;
import com.sro.authservice.dto.UserResponse;
import com.sro.authservice.model.User;
import com.sro.authservice.service.AuthService;
import com.sro.authservice.service.JwtService;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;

    public AuthController(AuthService authService, JwtService jwtService) {
        this.authService = authService;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @GetMapping(value = "/public-key", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> publicKey() {
        return ResponseEntity.ok(jwtService.getPublicKeyPem());
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponse> me(Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        List<String> roles = List.of(user.getRoles().split(","));
        return ResponseEntity.ok(new UserResponse(user.getEmail(), roles));
    }
}
