package com.mcueen.auth.service;

import com.mcueen.auth.controller.dto.user.LoginDto;
import com.mcueen.auth.controller.dto.user.LoginResponse;
import com.mcueen.auth.model.user.User;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends CommonService {
    void create(User user);

    LoginResponse login(LoginDto loginDto);

    Object getAll();
}
