package com.bugra.service;

import com.bugra.security.JwtTokenProvider;
import com.bugra.security.dto.TokenPayload;
import com.bugra.enums.Token;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private final JwtTokenProvider jwtTokenProvider;

    public JwtService(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public String createToken(Token token_name, TokenPayload payload) {
        return switch (token_name) {
            case access_token -> jwtTokenProvider.generateAccessToken(payload);
            case refresh_token -> jwtTokenProvider.generateRefreshToken(payload);
        };
    }

    public String getUserMailFromToken(String token) {
        return jwtTokenProvider.extractMail(token);
    }
    public boolean isTokenValid(String token, UserDetails userDetails) {
        return jwtTokenProvider.validateToken(token, userDetails);
    }

}
