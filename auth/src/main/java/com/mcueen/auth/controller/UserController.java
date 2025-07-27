package com.mcueen.auth.controller;


import com.mcueen.auth.controller.dto.UserCreateDto;
import com.mcueen.auth.exception.AuthServiceException;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping(value = "/users")
public class UserController {

    @Autowired
    private UserService userService;


    @PostMapping(value = "/sign-up")
    public ResponseEntity<?> create(@RequestBody UserCreateDto userCreateDto) throws AuthServiceException {
        User user = userService.mapUser(userCreateDto);
        userService.create(user);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }


    @GetMapping
    public ResponseEntity<?> getAll() {
        return new ResponseEntity<>(userService.getAll(), HttpStatus.OK);
    }
}
