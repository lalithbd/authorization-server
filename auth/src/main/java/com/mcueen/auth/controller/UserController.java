package com.mcueen.auth.controller;


import com.mcueen.auth.controller.dto.UserCreateDto;
import com.mcueen.auth.controller.dto.user.LoginDto;
import com.mcueen.auth.controller.dto.user.LoginResponse;
import com.mcueen.auth.exception.AuthServiceException;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/api/user")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping
    public ResponseEntity<String> getId() {
        return new ResponseEntity<>("OK", HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<LoginResponse> login(@RequestBody LoginDto loginDto) throws AuthServiceException {
        LoginResponse loginResponse = userService.login(loginDto);
        return new ResponseEntity<>(loginResponse, HttpStatus.ACCEPTED);
    }

    @PostMapping
    public ResponseEntity create(@RequestBody UserCreateDto userCreateDto) throws AuthServiceException {
        User user = userService.map(userCreateDto, User.class);
        userService.create(user);
        return new ResponseEntity(HttpStatus.CREATED);
    }
}
