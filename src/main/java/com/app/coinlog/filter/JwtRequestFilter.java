package com.app.coinlog.filter;

import com.app.coinlog.service.UserService;
import com.app.coinlog.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");
        String requestPath = request.getServletPath();
        // Bypass JWT validation for login and registration
        if (requestPath.equals("/api/auth/login") || requestPath.equals("/api/auth/register")) {
            chain.doFilter(request, response);
            return;
        }

        String username = null;
        String jwt = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            username = jwtUtil.extractUsername(jwt);
        }

        // If the token is valid, authenticate the user
        if (username != null && jwtUtil.validateToken(jwt, username)) {
            // Perform authentication (if needed, can be implemented here)
        }

        chain.doFilter(request, response);
    }

}
