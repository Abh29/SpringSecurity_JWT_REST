package com.example.springsecurity_jwt;

import com.example.springsecurity_jwt.model.AppUser;
import com.example.springsecurity_jwt.model.Role;
import com.example.springsecurity_jwt.service.AppUserService;
import lombok.extern.log4j.Log4j;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;

@SpringBootApplication @Slf4j
public class  SpringSecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtApplication.class, args);
    }

    // populate the DB on run
    @Bean
    CommandLineRunner run(AppUserService userService) {
        return args -> {
            
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_PROVIDER"));
            userService.saveRole(new Role(null, "ROLE_USER"));

            AppUser user = new AppUser(
                    null,
                    "applicationAdmin",
                    "admin",
                    "admin@test.com",
                    "adminSecret",
                    new ArrayList<>(),
                    null,
                    Timestamp.valueOf(LocalDateTime.now()),
                    Timestamp.valueOf(LocalDateTime.now()));

            log.info("user {}\n*******************************\n", user);
            userService.saveAppUser(user);

            userService.assignRoleToUser("admin", "ROLE_ADMIN");
            userService.assignRoleToUser("admin", "ROLE_PROVIDER");
            userService.assignRoleToUser("admin", "ROLE_USER");
        };
    }

}
