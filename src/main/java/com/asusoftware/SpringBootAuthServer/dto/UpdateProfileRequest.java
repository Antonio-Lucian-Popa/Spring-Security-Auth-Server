package com.asusoftware.SpringBootAuthServer.dto;

import lombok.Data;

import java.util.Set;

@Data
public class UpdateProfileRequest {
    private String email;
    private String firstName;
    private String lastName;
    private String password; // noua parolă (opțional)
    private Set<String> roles; // opțional, doar pentru ADMIN
}

