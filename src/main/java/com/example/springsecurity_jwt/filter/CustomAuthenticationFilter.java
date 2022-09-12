package com.example.springsecurity_jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    private final Algorithm algorithm;


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String userName = request.getParameter("userName");
        String password = request.getParameter("password");

        log.info("trying to authenticate user: {} with password: {} .", userName, password);

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userName, password);

        return authenticationManager.authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        User springUser = (User) authResult.getPrincipal();

        log.info("user {} pass {} {}", springUser.getUsername(), springUser.getPassword(), springUser.getAuthorities());

       // Algorithm = Algorithm.HMAC256(APPLICATION_SECRET);

        String accessToken = JWT.create()
                .withSubject(springUser.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 60000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim(
                        "roles",
                        springUser
                        .getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())
                        )
                .sign(algorithm);

        String refreshToken = JWT.create()
                .withSubject(springUser.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 60000 * 60 * 2))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);

/*        response.addHeader("access_token", accessToken);
        response.addHeader("refresh_token", refreshToken);*/

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        new ObjectMapper().writeValue(response.getOutputStream(), tokens);

    }


}
