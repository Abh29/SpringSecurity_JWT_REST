package com.example.springsecurity_jwt.repository;

import com.example.springsecurity_jwt.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findAppUserByUserName(String userName);
}
