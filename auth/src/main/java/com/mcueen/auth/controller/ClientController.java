package com.mcueen.auth.controller;


import com.mcueen.auth.controller.dto.UserCreateDto;
import com.mcueen.auth.exception.AuthServiceException;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.service.UserService;
import com.mcueen.auth.service.impl.JpaRegisteredClientService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping(value = "/clients")
public class ClientController {

    @Autowired
    private JpaRegisteredClientService registeredClientService;


    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> create(@RequestBody UserCreateDto userCreateDto) throws AuthServiceException {
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

//    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
//    public ResponseEntity<?> login(@RequestBody LoginDto loginDto, HttpServletRequest request, HttpServletResponse response) throws AuthServiceException {
//        UsernamePasswordAuthenticationToken authenticationToken = UsernamePasswordAuthenticationToken.unauthenticated(loginDto.getEmail(), loginDto.getPassword());
//        Authentication authentication = authenticationManager.authenticate(authenticationToken);
//        try {
//            successHandler.onAuthenticationSuccess(request, response, authentication);
//        } catch (IOException | ServletException e) {
//            throw new RuntimeException(e);
//        }
//        return new ResponseEntity<>(HttpStatus.OK);
//    }

    @GetMapping
    public ResponseEntity<?> getAll() {
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
