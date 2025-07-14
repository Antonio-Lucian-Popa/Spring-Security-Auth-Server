package com.asusoftware.SpringBootAuthServer.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {

    @NotBlank(message = "Username-ul este obligatoriu")
    private String username;

    @NotBlank(message = "Emailul este obligatoriu")
    @Email(message = "Emailul nu este valid")
    private String email;

    @NotBlank(message = "Parola este obligatorie")
    @Size(min = 6, message = "Parola trebuie să aibă cel puțin 6 caractere")
    private String password;

    private String firstName;
    private String lastName;
}