package com.asusoftware.SpringBootAuthServer.controller;

import com.asusoftware.SpringBootAuthServer.dto.*;
import com.asusoftware.SpringBootAuthServer.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.ok("Cont creat. Verifică emailul pentru activare.");
    }

    @PostMapping("/oauth/google")
    public ResponseEntity<AuthenticationResponse> loginWithGoogle(@RequestBody GoogleOAuthRequest request) {
        return ResponseEntity.ok(authService.loginWithGoogle(request.getIdToken()));
    }


    @GetMapping("/confirm")
    public ResponseEntity<?> confirm(@RequestParam("token") String token) {
        authService.confirmAccount(token);
        return ResponseEntity.ok("Cont activat cu succes!");
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refresh(@RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        authService.sendResetPasswordEmail(email);
        return ResponseEntity.ok("Email trimis cu link de resetare (dacă userul există).");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestParam String newPassword) {
        authService.resetPassword(token, newPassword);
        return ResponseEntity.ok("Parolă resetată cu succes.");
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponse> getProfile(@AuthenticationPrincipal UserDetails userDetails) {
        UserResponse userResponse = authService.getProfile(userDetails);
        return ResponseEntity.ok(userResponse);
    }

    @PutMapping("/profile")
    public ResponseEntity<?> updateProfile(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody UpdateProfileRequest request
    ) {
        authService.updateProfile(userDetails, request);
        return ResponseEntity.ok("Profil actualizat cu succes.");
    }


}

