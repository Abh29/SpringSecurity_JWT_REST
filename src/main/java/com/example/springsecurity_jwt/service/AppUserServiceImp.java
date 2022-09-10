package com.example.springsecurity_jwt.service;

import com.example.springsecurity_jwt.model.AppUser;
import com.example.springsecurity_jwt.model.Role;
import com.example.springsecurity_jwt.repository.AppUserRepository;
import com.example.springsecurity_jwt.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class AppUserServiceImp implements AppUserService{

    private final AppUserRepository userRepository;
    private final RoleRepository roleRepository;


    @Override
    public AppUser saveAppUser(AppUser user) {
        log.info("saving a new User to the DB");
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
}
