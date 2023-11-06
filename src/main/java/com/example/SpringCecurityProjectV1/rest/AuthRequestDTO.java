package com.example.SpringCecurityProjectV1.rest;

import lombok.Data;

@Data
public class AuthRequestDTO {

    private String email;
    private String password;
}
