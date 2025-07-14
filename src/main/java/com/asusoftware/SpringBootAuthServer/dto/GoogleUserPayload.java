package com.asusoftware.SpringBootAuthServer.dto;

import lombok.Data;

@Data
public class GoogleUserPayload {
    private String email;
    private String name;
    private String sub;  // Google user ID
    private String aud;  // client ID
}

