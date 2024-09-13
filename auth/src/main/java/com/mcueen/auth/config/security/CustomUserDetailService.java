package com.mcueen.auth.config.security;

import com.mcueen.auth.model.user.RolePermission;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.model.user.UserRole;
import com.mcueen.auth.repository.UserRepository;
import com.mcueen.auth.service.RolePermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class CustomUserDetailService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RolePermissionService rolePermissionService;
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
}
