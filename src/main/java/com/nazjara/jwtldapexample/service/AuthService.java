package com.nazjara.jwtldapexample.service;

import com.nazjara.jwtldapexample.model.JwtTokenData;
import com.nazjara.jwtldapexample.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.List;

@RequiredArgsConstructor
@Service
public class AuthService {
    private final TokenService tokenService;

    private final AuthenticationProvider authProvider;

    public JwtTokenData authenticate(String username, String password) throws AuthenticationException {
        var authentication = authProvider.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));

        // get roles, permissions

        var userDetails = new User(username, List.of("role"), List.of(new SimpleGrantedAuthority("permission")));

        var tokenData = tokenService.generateJwtTokenData(userDetails);
        // save token to the repo

        return tokenData;
    }

    public User authorize(String accessToken) throws AuthenticationException {
        return tokenService.getUser(accessToken);
    }

    public void logout(String accessToken) {
        // deactivate token
    }

    public JwtTokenData refreshToken(String refreshToken) {
        var user = tokenService.getUser(refreshToken);

        // deactivate token

        var tokenData = tokenService.generateJwtTokenData(user);

        // save token to the repo

        return tokenData;
    }
}
