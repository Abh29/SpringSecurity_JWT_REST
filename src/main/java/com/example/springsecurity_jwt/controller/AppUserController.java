package com.example.springsecurity_jwt.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.springsecurity_jwt.form.RoleToAppUserForm;
import com.example.springsecurity_jwt.model.AppUser;
import com.example.springsecurity_jwt.model.Role;
import com.example.springsecurity_jwt.service.AppUserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;

@Controller
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class AppUserController  {

    private final AppUserService userService;

    private final Algorithm algorithm;

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


    @GetMapping("/token/refresh")
    public void refreshAccessToken(HttpServletRequest request, HttpServletResponse response) throws IOException {

            log.info("requesting token refresh");
            String authorizationHeader = request.getHeader(AUTHORIZATION);

            if (authorizationHeader != null && authorizationHeader.startsWith("bearer ")){
                try {
                    // get the refresh token
                    String refreshToken = authorizationHeader.substring("bearer ".length());
                    log.info("refresh token {}", refreshToken);
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = verifier.verify(refreshToken);

                    // decode the refresh token and get the user
                    String userName = decodedJWT.getSubject();
                    AppUser appUser = userService.getAppUser(userName).get();

                    // create a new access token
                    String accessToken = JWT.create()
                            .withSubject(appUser.getUserName())
                            .withExpiresAt(new Date(System.currentTimeMillis() + 60 * 1000))
                            .withIssuer(request.getRequestURL().toString())
                            .withClaim(
                                    "roles",
                                    appUser.getRoles()
                                            .stream()
                                            .map(Role::getName)
                                            .collect(Collectors.toList())
                            )
                            .sign(algorithm);

                    // send the new token

                    Map<String, String> tokens = new HashMap<>();
                    tokens.put("access_token", accessToken);
                    tokens.put("refresh_token", refreshToken);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                    new ObjectMapper().writeValue(response.getOutputStream(), tokens);

                } catch (Exception e) {
                    response.setStatus(FORBIDDEN.value());
                    Map<String, String> error = new HashMap<>();
                    error.put("error", e.getMessage());
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }
            }
    }

}
