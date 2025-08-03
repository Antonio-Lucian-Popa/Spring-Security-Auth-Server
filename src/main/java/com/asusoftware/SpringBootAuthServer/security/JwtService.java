package com.asusoftware.SpringBootAuthServer.security;

import com.asusoftware.SpringBootAuthServer.model.Role;
import com.asusoftware.SpringBootAuthServer.model.User;
import com.asusoftware.SpringBootAuthServer.repository.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token-expiration-minutes}")
    private int accessTokenMinutes;

    @Value("${jwt.refresh-token-expiration-days}")
    private int refreshTokenDays;

    private final UserRepository userRepository;

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(User user) {
        return Jwts.builder()
                .setSubject(user.getId().toString())
                .claim("roles", user.getRoles().stream().map(Role::getName).toList())
                .claim("firstName", user.getFirstName())
                .claim("lastName", user.getLastName())
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plus(accessTokenMinutes, ChronoUnit.MINUTES)))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(User user) {
        return Jwts.builder()
                .setSubject(user.getId().toString())
                .claim("type", "REFRESH")
                .claim("firstName", user.getFirstName())
                .claim("lastName", user.getLastName())
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plus(refreshTokenDays, ChronoUnit.DAYS)))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateActivationToken(User user) {
        return Jwts.builder()
                .setSubject(user.getId().toString())
                .claim("type", "ACTIVATION")
                .claim("firstName", user.getFirstName())
                .claim("lastName", user.getLastName())
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateResetToken(User user) {
        return Jwts.builder()
                .setSubject(user.getId().toString())
                .claim("type", "RESET")
                .claim("firstName", user.getFirstName())
                .claim("lastName", user.getLastName())
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plus(30, ChronoUnit.MINUTES))) // valabil 30 min
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    public boolean isValidToken(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public boolean isValidRefreshToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return "REFRESH".equals(claims.get("type")) &&
                    claims.getExpiration().after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public UUID extractUserId(String token) {
        return UUID.fromString(extractAllClaims(token).getSubject());
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final UUID userId = extractUserId(token);
            final User user = userRepository.findById(userId)
                    .orElse(null);
            return (user != null && user.getEmail().equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        Date expiration = extractAllClaims(token).getExpiration();
        return expiration.before(new Date());
    }

}

