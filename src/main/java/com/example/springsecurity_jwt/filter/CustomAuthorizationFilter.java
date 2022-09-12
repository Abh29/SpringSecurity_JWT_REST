package com.example.springsecurity_jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;

@RequiredArgsConstructor
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    private final Algorithm algorithm;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/login") || request.getServletPath().equals("/api/token/refresh")) {
            log.info("authorizing request -> {}", request.getServletPath());
            filterChain.doFilter(request, response);
        } else {

            log.info("authorizing a request to {}", request.getServletPath());
            String authorizationHeader = request.getHeader(AUTHORIZATION);

            log.info("authorization header {}", authorizationHeader);

            if (authorizationHeader != null && authorizationHeader.startsWith("bearer ")){
                try {
                    String token = authorizationHeader.substring("bearer ".length());
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = verifier.verify(token);

                    String userName = decodedJWT.getSubject();
                    List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    decodedJWT.getClaim("roles").asList(String.class).forEach(
                            role -> {
                                authorities.add(new SimpleGrantedAuthority(role));
                    });

                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userName, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                } catch (Exception e) {
                    log.error("Error while authorizing requtest {}", e.getMessage());
                    response.setStatus(FORBIDDEN.value());
                    Map<String, String> error = new HashMap<>();
                    error.put("error", e.getMessage());
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                    return;
                }
            }
            filterChain.doFilter(request, response);
        }
    }
}
