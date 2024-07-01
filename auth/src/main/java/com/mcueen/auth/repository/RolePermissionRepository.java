package com.mcueen.auth.repository;

import com.mcueen.auth.model.user.RolePermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RolePermissionRepository extends JpaRepository<RolePermission, Long> {

    @Query("SELECT rp FROM RolePermission rp WHERE rp.role.id = :id ")
    List<RolePermission> getByRoleId(@Param("id") Long id);
}
