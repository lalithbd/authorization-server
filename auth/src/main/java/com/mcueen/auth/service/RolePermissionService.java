package com.mcueen.auth.service;

import com.mcueen.auth.model.user.RolePermission;
import com.mcueen.auth.model.user.UserRole;

import java.util.List;

public interface RolePermissionService extends CommonService {
    List<UserRole> getUserRolesByUserId(Long id);

    List<RolePermission> getRolePermissionsByRoleId(Long id);
}
