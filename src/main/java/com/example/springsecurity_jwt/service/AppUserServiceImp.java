package com.example.springsecurity_jwt.service;

import com.example.springsecurity_jwt.model.AppUser;
import com.example.springsecurity_jwt.model.Role;
import com.example.springsecurity_jwt.repository.AppUserRepository;
import com.example.springsecurity_jwt.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class AppUserServiceImp implements AppUserService, UserDetailsService {

    private final AppUserRepository userRepository;
    private final RoleRepository roleRepository;

    private final PasswordEncoder passwordEncoder;


    @Override
    public AppUser saveAppUser(AppUser user) {
        log.info("saving a new User to the DB");
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving a new Role to the DB");
        return roleRepository.save(role);
    }

    @Override
    public void assignRoleToUser(String userName, String roleName) {
        log.info("assigning Role {} to user {}", roleName, userName);
        Optional<AppUser> user = userRepository.findAppUserByUserName(userName);
        if (!user.isPresent())
            throw new RuntimeException("user " + userName + " not found in the DB!");
        Optional<Role> role = roleRepository.findRoleByName(roleName);
        if (!role.isPresent())
            return;
        user.get().getRoles().add(role.get());
    }

    @Override
    public List<AppUser> getAppUsers() {
        log.info("get all the users");
        return userRepository.findAll();
    }

    public Optional<AppUser> getAppUser(String userName) {
        log.info("get user {}", userName);
        return userRepository.findAppUserByUserName(userName);
    }

    // this method is from UserDetailsService interface
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<AppUser> appUser = getAppUser(username);
        if (appUser.isEmpty())
            throw new UsernameNotFoundException("this userName: " + username + " is not found !");

        log.info("user {} loaded ! with pass {}", username, appUser.get().getPassword());

        List<SimpleGrantedAuthority> authorities = new ArrayList<>(3);

        appUser.get().getRoles().forEach(
                role -> {
                    authorities.add(new SimpleGrantedAuthority(role.getName()));
                }
        );

        //org.springframework.security.core.userdetails.User;
        User user = new User(appUser.get().getUserName(), appUser.get().getPassword(), authorities);

        log.info("springUser {} {}", user.getUsername(), user.getPassword());

        return user;
    }
}
