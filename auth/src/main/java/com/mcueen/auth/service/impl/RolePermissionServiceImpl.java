package com.mcueen.auth.service.impl;

import com.mcueen.auth.model.user.RolePermission;
import com.mcueen.auth.model.user.UserRole;
import com.mcueen.auth.repository.RolePermissionRepository;
import com.mcueen.auth.repository.UserRoleRepository;
import com.mcueen.auth.service.RolePermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
public class RolePermissionServiceImpl implements RolePermissionService {

    @Autowired
    private RolePermissionRepository rolePermissionRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Override
    public List<UserRole> getUserRolesByUserId(Long id) {
        return userRoleRepository.getByUserId(id);
    }

    @Override
    public List<RolePermission> getRolePermissionsByRoleId(Long id) {
        return rolePermissionRepository.getByRoleId(id);
    }
}
