package com.example.springsecurity_jwt.service;

import com.example.springsecurity_jwt.model.AppUser;
import com.example.springsecurity_jwt.model.Role;

import java.util.List;
import java.util.Optional;

public interface AppUserService {
    AppUser saveAppUser(AppUser user);
    Role saveRole(Role role);
    void assignRoleToUser(String userName, String roleName);
    List<AppUser> getAppUsers(); // change this to pagination

    Optional<AppUser> getAppUser(String userName);

}
