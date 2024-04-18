package com.nazjara.jwtldapexample.controller;

import com.nazjara.jwtldapexample.dto.AuthenticationRequest;
import com.nazjara.jwtldapexample.model.JwtTokenData;
import com.nazjara.jwtldapexample.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Validated
public class AuthenticationController
{
    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<JwtTokenData> login(@RequestBody AuthenticationRequest request)
    {
        var userTokenData = authService.authenticate(request.getUsername(), request.getPassword());
        return ResponseEntity.ok(userTokenData);
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.OK)
    public void logout(HttpServletRequest request, Authentication authentication)
    {
        authService.logout(request.getHeader("Authorization"));
        log.info(String.format("User logout passed for user %s", authentication.getPrincipal()));
    }

    @GetMapping("/refresh-token")
    public ResponseEntity<JwtTokenData> refreshToken(HttpServletRequest request)
    {
        return ResponseEntity.ok(authService.refreshToken(request.getHeader("Authorization")));
    }
}
