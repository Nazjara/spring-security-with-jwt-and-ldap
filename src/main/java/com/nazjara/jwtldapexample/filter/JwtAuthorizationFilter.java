package com.nazjara.jwtldapexample.filter;

import com.nazjara.jwtldapexample.service.AuthService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter
{
    private final AuthService authService;

    @SuppressWarnings("checkstyle:EmptyBlock")
    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException
    {
        var token = request.getHeader("Authorization");

        if (null != token)
        {
            try
            {
                SecurityContextHolder.getContext().setAuthentication(authService.authorize(token));
            } catch (Exception ignored)
            {
            }
        }

        filterChain.doFilter(request, response);
    }
}
