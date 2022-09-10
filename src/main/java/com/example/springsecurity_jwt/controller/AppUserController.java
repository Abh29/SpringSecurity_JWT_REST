package com.example.springsecurity_jwt.controller;

import com.example.springsecurity_jwt.form.RoleToAppUserForm;
import com.example.springsecurity_jwt.model.AppUser;
import com.example.springsecurity_jwt.model.Role;
import com.example.springsecurity_jwt.service.AppUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@Controller
@RequestMapping("/api")
@RequiredArgsConstructor
public class AppUserController  {

    private final AppUserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<AppUser>> getUsers() {
        return ResponseEntity.ok(userService.getAppUsers());
    }

    @PostMapping("/user/save")
    public ResponseEntity<AppUser> saveAppUser(@RequestBody AppUser user) {
        return ResponseEntity.created(
                URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString())
        ).body(userService.saveAppUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        return ResponseEntity.created(
                URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString())
        ).body(userService.saveRole(role));
    }

    @PostMapping("/role/assignTo")
    public ResponseEntity<?> assignRoleToAppUser(@RequestBody RoleToAppUserForm form) {
        userService.assignRoleToUser(form.getUserName(), form.getRoleName());
        return ResponseEntity.ok().build();
    }
}
