package com.mcueen.auth.service.impl;

import com.mcueen.auth.controller.dto.UserCreateDto;
import com.mcueen.auth.exception.AuthServiceException;
import com.mcueen.auth.model.user.Role;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.model.user.UserRole;
import com.mcueen.auth.repository.UserRepository;
import com.mcueen.auth.service.RolePermissionService;
import com.mcueen.auth.service.UserService;
import com.mcueen.auth.util.UserUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
@Slf4j
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private RolePermissionService rolePermissionService;

    @Override
    public void create(User user) throws AuthServiceException {
        if(existsByEmail(user.getEmail())){
            log.warn("Email already exists : {}", user.getEmail());
            throw new AuthServiceException(HttpStatus.BAD_REQUEST, "Email already exists");
        }
        user.setPassword(encoder.encode(user.getPassword()));
        List<UserRole> userRoles = user.getUserRoles();
        if(userRoles == null || userRoles.isEmpty()) {
            Role role = rolePermissionService.getRoleByName(UserUtil.DEFAULT_ROLE);
            if(role == null) {
                log.warn("Cannot find default role : {} ", UserUtil.DEFAULT_ROLE);
            }
            user.setUserRoles(new ArrayList<>(Collections.singleton(
                    UserRole.builder()
                            .role(role)
                            .user(user).build()
            )));
        }
        userRepository.save(user);
    }

    @Override
    public Object getAll() {
        return userRepository.findAll();
    }

    @Override
    public User findByEmail(String username) {
        Optional<User> user = userRepository.findByEmail(username);
        return user.orElse(null);
    }

    private boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public User findById(Long userId) {
        return userRepository.getReferenceById(userId);
    }

    @Override
    public User mapUser(UserCreateDto userCreateDto) throws AuthServiceException {
        String password = userCreateDto.getPassword();
        String confirmPassword = userCreateDto.getConfirmPassword();
        User user = map(userCreateDto, User.class);
        if(password.equals(confirmPassword)) {
            if(!UserUtil.isValidPassword(password)){
                log.error("Invalid password complexity");
                throw new AuthServiceException(HttpStatus.BAD_REQUEST, "Invalid password complexity");
            }
        } else {
            log.error("password and confirm password should be same");
            throw new AuthServiceException(HttpStatus.BAD_REQUEST, "password and confirm password should be same");
        }
        return user;
    }
}
