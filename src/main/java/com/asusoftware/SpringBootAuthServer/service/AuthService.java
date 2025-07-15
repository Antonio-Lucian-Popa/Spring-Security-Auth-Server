package com.asusoftware.SpringBootAuthServer.service;

import com.asusoftware.SpringBootAuthServer.dto.*;
import com.asusoftware.SpringBootAuthServer.model.Role;
import com.asusoftware.SpringBootAuthServer.model.User;
import com.asusoftware.SpringBootAuthServer.repository.RoleRepository;
import com.asusoftware.SpringBootAuthServer.repository.UserRepository;
import com.asusoftware.SpringBootAuthServer.security.JwtService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final EmailService emailService;

    @Value("${google.client-id}")
    private String googleClientId;

    @Value("${frontend.url}")
    private String frontendUrl;

    public AuthenticationResponse login(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return new AuthenticationResponse(accessToken, refreshToken);
    }

    public void register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email deja înregistrat.");
        }

        Role defaultRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Rolul USER nu există în DB"));

        User user = User.builder()
                .email(request.getEmail())
                .username(request.getEmail())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .password(passwordEncoder.encode(request.getPassword()))
                .enabled(false)
                .roles(Set.of(defaultRole))
                .createdAt(new Date().toInstant())
                .build();

        userRepository.save(user);

        String activationToken = jwtService.generateActivationToken(user);
        String activationLink = frontendUrl + "/activate?token=" + activationToken;

        Map<String, Object> model = new HashMap<>();
        model.put("name", user.getFirstName());
        model.put("activationLink", activationLink);

        emailService.sendHtmlEmail(user.getEmail(), "Activare cont", "activation-email", model);

    }

    public void confirmAccount(String token) {
        if (!jwtService.isValidToken(token)) {
            throw new IllegalArgumentException("Token invalid sau expirat.");
        }

        Claims claims = jwtService.extractAllClaims(token);
        String email = claims.getSubject();
        String type = (String) claims.get("type");

        if (!"ACTIVATION".equals(type)) {
            throw new IllegalArgumentException("Token invalid pentru activare.");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (Boolean.TRUE.equals(user.getEnabled())) {
            throw new IllegalStateException("Cont deja activat.");
        }

        user.setEnabled(true);
        userRepository.save(user);
    }

    public AuthenticationResponse refreshToken(RefreshTokenRequest request) {
        if (!jwtService.isValidRefreshToken(request.getRefreshToken())) {
            throw new RuntimeException("Token invalid");
        }

        String email = jwtService.extractEmail(request.getRefreshToken());
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String newAccessToken = jwtService.generateAccessToken(user);
        return new AuthenticationResponse(newAccessToken, request.getRefreshToken());
    }

    public AuthenticationResponse loginWithGoogle(String idToken) {
        GoogleUserPayload payload = validateGoogleToken(idToken);

        Optional<User> optionalUser = userRepository.findByEmail(payload.getEmail());

        User user = optionalUser.orElseGet(() -> {
            Role role = roleRepository.findByName("USER")
                    .orElseThrow(() -> new RuntimeException("Rolul USER lipsă"));

            User newUser = User.builder()
                    .email(payload.getEmail())
                    .username(payload.getEmail())
                    .firstName(payload.getName())
                    .lastName(payload.getName())
                    .password(passwordEncoder.encode(UUID.randomUUID().toString())) // Parolă generată automat
                    .enabled(true)
                    .roles(Set.of(role))
                    .createdAt(new Date().toInstant())
                    .build();

            return userRepository.save(newUser);
        });

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        return new AuthenticationResponse(accessToken, refreshToken);
    }

    public GoogleUserPayload validateGoogleToken(String idToken) {
        String googleApiUrl = "https://oauth2.googleapis.com/tokeninfo?id_token=" + idToken;

        RestTemplate restTemplate = new RestTemplate();

        try {
            ResponseEntity<GoogleUserPayload> response = restTemplate.getForEntity(
                    googleApiUrl, GoogleUserPayload.class
            );

            GoogleUserPayload payload = response.getBody();

            // Validare simplă (verifică că e pentru aplicația ta)
            if (payload == null || !payload.getAud().equals(googleClientId)) {
                throw new RuntimeException("Token invalid: audiență incorectă");
            }

            return payload;
        } catch (HttpClientErrorException ex) {
            throw new RuntimeException("Token invalid sau expirat", ex);
        }
    }

    public void sendResetPasswordEmail(String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            String token = jwtService.generateResetToken(user); // vei crea metoda asta
            String link = frontendUrl + "/reset-password?token=" + token;

            Map<String, Object> model = new HashMap<>();
            model.put("name", user.getFirstName());
            model.put("resetLink", link);

            emailService.sendHtmlEmail(user.getEmail(), "Resetare parolă", "reset-password-email", model);

        }
    }


    public void resetPassword(String token, String newPassword) {
        if (!jwtService.isValidToken(token)) {
            throw new IllegalArgumentException("Token invalid sau expirat.");
        }

        Claims claims = jwtService.extractAllClaims(token);
        String type = (String) claims.get("type");
        if (!"RESET".equals(type)) {
            throw new IllegalArgumentException("Token invalid pentru resetare parolă.");
        }

        String email = claims.getSubject();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }


}

