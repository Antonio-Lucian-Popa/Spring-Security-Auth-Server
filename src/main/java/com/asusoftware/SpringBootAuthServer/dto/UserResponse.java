package com.asusoftware.SpringBootAuthServer.dto;

import com.asusoftware.SpringBootAuthServer.model.Role;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Builder
@Data
public class UserResponse {
    private UUID id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private Set<String> roles;
    private Instant createdAt;
    private boolean enabled;

    public UserResponse(UUID id, String username, String email, String firstName, String lastName, Set<String> role, Instant createdAt, boolean enabled) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.roles = role;
        this.createdAt = createdAt;
        this.enabled = enabled;
    }
}
