package com.mcueen.auth.controller.dto;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserCreateDto {
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private String confirmPassword;
}
