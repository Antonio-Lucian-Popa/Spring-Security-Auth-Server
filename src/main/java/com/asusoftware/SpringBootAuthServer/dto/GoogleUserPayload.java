package com.asusoftware.SpringBootAuthServer.dto;

import lombok.Data;

@Data
public class GoogleUserPayload {
    private String email;
    private String name;
    private String given_name;  // First name
    private String family_name;  // Last name
    private String sub;  // Google user ID
    private String aud;  // client ID
}

