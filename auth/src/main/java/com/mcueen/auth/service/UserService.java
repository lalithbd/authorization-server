package com.mcueen.auth.service;

import com.mcueen.auth.controller.dto.user.LoginDto;
import com.mcueen.auth.controller.dto.user.LoginResponse;
import com.mcueen.auth.model.user.User;

public interface UserService extends CommonService {
    void create(User user);

    LoginResponse login(LoginDto loginDto);

    Object getAll();

    User findByEmail(String username);

    User findById(Long userId);
}
