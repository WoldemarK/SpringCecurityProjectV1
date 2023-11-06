package com.example.SpringCecurityProjectV1.security.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import javax.security.sasl.AuthenticationException;
@Getter
public class JwtAuthException extends AuthenticationException {
    private HttpStatus status;
    public JwtAuthException(String detail) {
        super(detail);
    }
    public JwtAuthException(String detail, HttpStatus status) {
        super(detail);
        this.status = status;
    }
}
