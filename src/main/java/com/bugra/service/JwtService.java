package com.bugra.service;

import com.bugra.model.User;
import com.bugra.security.JwtTokenProvider;
import com.bugra.security.dto.TokenPayload;
import com.bugra.security.dto.TokensRefreshed;
import com.bugra.enums.Token;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;


import static com.bugra.enums.Token.access_token;
import static com.bugra.enums.Token.refresh_token;

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
