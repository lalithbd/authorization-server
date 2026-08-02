package com.mcueen.auth.controller.dto;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserCreateDto {

    private Long id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;
}
