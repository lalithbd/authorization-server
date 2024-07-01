package com.mcueen.auth.service.impl;

import com.mcueen.auth.config.security.UserDetailsModel;
import com.mcueen.auth.controller.dto.user.LoginDto;
import com.mcueen.auth.controller.dto.user.LoginResponse;
import com.mcueen.auth.model.user.*;
import com.mcueen.auth.repository.UserRepository;
import com.mcueen.auth.service.RolePermissionService;
import com.mcueen.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService, UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private RolePermissionService rolePermissionService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByEmail(username);
        if(user.isPresent()) {
            User presentUser = user.get();
            List<UserRole> userRoles = rolePermissionService.getUserRolesByUserId(presentUser.getId());
            userRoles.forEach(userRole -> {
                List<RolePermission> rolePermissions = rolePermissionService.getRolePermissionsByRoleId(userRole.getRole().getId());
                userRole.getRole().setRolePermissions(rolePermissions);
            });
            presentUser.setUserRoles(userRoles);
            return new UserDetailsModel(presentUser);
        } else {
            throw new UsernameNotFoundException("User not found");
        }
    }

    @Override
    public void create(User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        userRepository.save(user);
    }

    @Override
    public LoginResponse login(LoginDto loginDto) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword()));
        return new LoginResponse("asdasdad", "dsdsdsdsd");
    }
}
