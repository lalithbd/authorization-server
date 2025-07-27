package com.mcueen.auth.service;

import com.mcueen.auth.controller.dto.UserCreateDto;
import com.mcueen.auth.exception.AuthServiceException;
import com.mcueen.auth.model.user.User;

public interface UserService extends CommonService {

    void create(User user) throws AuthServiceException;

    Object getAll();

    User findByEmail(String username);

    User findById(Long userId);

    User mapUser(UserCreateDto userCreateDto) throws AuthServiceException;
}
