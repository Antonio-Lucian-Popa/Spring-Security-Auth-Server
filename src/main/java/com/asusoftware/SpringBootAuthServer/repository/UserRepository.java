package com.asusoftware.SpringBootAuthServer.repository;

import com.asusoftware.SpringBootAuthServer.model.User;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    Optional<User> findByUsername(String username);

    boolean existsByEmail(@NotBlank(message = "Emailul este obligatoriu") @Email(message = "Emailul nu este valid") String email);
}
