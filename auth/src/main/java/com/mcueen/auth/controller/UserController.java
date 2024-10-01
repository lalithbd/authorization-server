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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/user")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private AuthenticationManager authenticationManager;


    @PostMapping(value = "/signup")
    public ResponseEntity<?> create(@RequestBody UserCreateDto userCreateDto) throws AuthServiceException {
        User user = userService.map(userCreateDto, User.class);
        userService.create(user);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @PostMapping(value = "/login")
    public ResponseEntity<?> login(@RequestBody LoginDto loginDto) throws AuthServiceException {
        UsernamePasswordAuthenticationToken authenticationToken = UsernamePasswordAuthenticationToken.unauthenticated(loginDto.getEmail(), loginDto.getPassword());
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
