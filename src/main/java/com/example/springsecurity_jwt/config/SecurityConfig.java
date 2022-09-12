package com.example.springsecurity_jwt.config;

import com.auth0.jwt.algorithms.Algorithm;
import com.example.springsecurity_jwt.filter.CustomAuthenticationFilter;
import com.example.springsecurity_jwt.filter.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;


@Configuration
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    /**
     * instead of using extends WebSecurityConfigurerAdapter and then overriding
     * void configure(WebSecurity)
     * void configure(AuthenticationManagerBuilder)
     * export AuthenticationManager authenticationManagerBean()
     *
     *
     * Step 1: Remove WebSecurityConfigurerAdapter
     * Step 2: Export SecurityFilterChain bean
     * Step 3: Replace public configure method
     * Step 4: Export AuthenticationManager bean
     *
     *
     * we use this approach:
     * from 1 and 2
     * export SecurityFilterChain filterChain(HttpSecurity) with @Bean
     * where we set our http configuration
     * from 3
     * we replace the first configure() with WebSecurityCustomizer() bean
     * and for the second configure() we export DaoAuthenticationProvider authProvider() with @Bean
     * and then use it inside filterChain() where we set our http.authenticationProvider()
     * from 4
     * we export AuthenticationManager using AuthenticationConfiguration
     *
     * note that we don't have these two beans we need to create them in a config class
     * for UserDetailsService we implement the interface in our AppUserService class
     *
     * */

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder bCryptPasswordEncoder;

    private final Algorithm algorithm;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{

        httpSecurity.csrf().disable();
        httpSecurity.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        httpSecurity.authorizeRequests().antMatchers("/login/**", "/api/token/refresh/**").permitAll();
        httpSecurity.authorizeRequests().antMatchers(POST, "/api/role/**").hasAnyAuthority("ROLE_ADMIN");
        httpSecurity.authorizeRequests().antMatchers(GET, "/api/users").hasAnyAuthority("ROLE_USER");
        httpSecurity.authorizeRequests().anyRequest().authenticated();


        httpSecurity.addFilter(new CustomAuthenticationFilter(authenticationManager(), algorithm));
        httpSecurity.addFilterBefore(new CustomAuthorizationFilter(algorithm), UsernamePasswordAuthenticationFilter.class);

        // set the authenticationProvider
        httpSecurity.authenticationProvider(authenticationProvider());

        return httpSecurity.build();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();

        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(bCryptPasswordEncoder);

        return authenticationProvider;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> {

        };
    }


/*
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
*/

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return new ProviderManager(authenticationProvider());
    }

}
