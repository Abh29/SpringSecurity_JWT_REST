package com.example.springsecurity_jwt.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.UniqueElements;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Null;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;

@Entity
@Table(name = "app_user")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AppUser {
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        @Column(name = "id", nullable = false)
        private Long id;
        private String name;
        private String userName;
        @Email @NotNull
        private String email;
        @NotNull @NotEmpty
        private String password;
        @ManyToMany(fetch = FetchType.EAGER)
        private Collection<Role> roles = new ArrayList<>();
        @Column(nullable = true)
        private Timestamp emailVerifiedAt;
        private Timestamp createAt;
        private Timestamp modifiedAt;
}