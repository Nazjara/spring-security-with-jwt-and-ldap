package com.nazjara.jwtldapexample.service;

import com.nazjara.jwtldapexample.model.JwtTokenData;
import com.nazjara.jwtldapexample.model.User;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class TokenService {

    @Value("${security.jwt.access-token-expiration-seconds}")
    private int accessTokenExpirationSeconds;

    @Value("${security.jwt.refresh-token-expiration-seconds}")
    private int refreshTokenExpirationSeconds;

    @Value("${security.jwt.secret}")
    private String secret;

    public JwtTokenData generateJwtTokenData(User user) {
        var id = UUID.randomUUID();
        var accessTokenExpirationTime = LocalDateTime.now().plusSeconds(accessTokenExpirationSeconds);
        var refreshTokenExpirationTime = LocalDateTime.now().plusSeconds(refreshTokenExpirationSeconds);
        var permissions = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        return JwtTokenData.builder()
                .id(id)
                .username(user.getPrincipal())
                .accessToken(JwtTokenData.TokenData.builder()
                        .expirationTime(accessTokenExpirationTime)
                        .token(generateToken(id, user, accessTokenExpirationTime, "ACCESS"))
                        .build())
                .refreshToken(JwtTokenData.TokenData.builder()
                        .expirationTime(refreshTokenExpirationTime)
                        .token(generateToken(id, user, refreshTokenExpirationTime, "REFRESH"))
                        .build())
                .roles(user.roles())
                .permissions(permissions)
                .blocked(false)
            .build();
    }

    public User getUser(String token) {
        var claims = decodeToken(token);

        var authorities = ((List<String>) claims.get("permissions", List.class)).stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return new User(claims.get("login", String.class), claims.get("roles", List.class), authorities);
    }

    private Claims decodeToken(String accessToken) {
        JwtParser parser = Jwts.parser().verifyWith(getKey()).build();
        try {
            return parser.parseSignedClaims(accessToken).getPayload();
        } catch (JwtException | IllegalArgumentException exception) {
            // throw exception
            return null;
        }
    }

    private String generateToken(UUID id, User user, LocalDateTime expirationTime, String tokenType) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", id);
        claims.put("login", user.getPrincipal());
        claims.put("roles", user.getAuthorities());
        claims.put("type", tokenType);
        claims.put("permissions",
                user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));

        return Jwts.builder()
                .claims(claims)
                .subject(user.getPrincipal())
                .issuedAt(new Date())
                .expiration(Date.from(expirationTime.atZone(ZoneId.systemDefault()).toInstant()))
                .signWith(getKey())
                .compact();
    }

    private SecretKey getKey() {
        return new SecretKeySpec(secret.getBytes(), "HmacSHA256");
    }
}
