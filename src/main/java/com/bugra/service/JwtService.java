package com.bugra.service;

import com.bugra.model.User;
import com.bugra.security.JwtTokenProvider;
import com.bugra.security.dto.TokenPayload;
import com.bugra.security.dto.TokensRefreshed;
import com.bugra.types.Token;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;


import static com.bugra.types.Token.access_token;
import static com.bugra.types.Token.refresh_token;

@Service
public class JwtService {

    private final JwtTokenProvider jwtTokenProvider;
    private final CookieService cookieService;
    private final RefreshTokenService refreshTokenService;

    public JwtService(JwtTokenProvider jwtTokenProvider, CookieService cookieService, RefreshTokenService refreshTokenService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.cookieService = cookieService;
        this.refreshTokenService = refreshTokenService;
    }

    public void setJwtCookies(String accessToken, String refreshToken, HttpServletResponse response) {
        ResponseCookie accessCookie = cookieService.setTokensInCookies(access_token.toString(),accessToken);
        ResponseCookie refreshCookie = cookieService.setTokensInCookies(refresh_token.toString(),refreshToken);
        response.addHeader("Set-Cookie", accessCookie.toString());
        response.addHeader("Set-Cookie", refreshCookie.toString());
    }

    public String createToken(Token token_name, TokenPayload payload) {
        return switch (token_name) {
            case access_token -> jwtTokenProvider.generateAccessToken(payload);
            case refresh_token -> jwtTokenProvider.generateRefreshToken(payload);
        };
    }

    public void refreshToken(User user,HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = cookieService.extractTokenFromCookies(refresh_token.toString(), request);
        refreshTokenService.removeRefreshToken(refreshToken);
        TokensRefreshed tokens = refreshTokenService.refreshTokens(user);
        setJwtCookies(tokens.access_token(), tokens.refresh_token(), response);
    }

    public String getUserIdFromCookieService(HttpServletRequest request) {
        return cookieService.getUserIdFromCookies(request);
    }

    public String getTokenFromCookie(String tokenName, HttpServletRequest request) {
        return cookieService.extractTokenFromCookies(tokenName, request);
    }

    public String getUserMailFromToken(String token) {
        return jwtTokenProvider.extractMail(token);
    }
    public boolean isTokenValid(String token, UserDetails userDetails) {
        return jwtTokenProvider.validateToken(token, userDetails);
    }
    public void saveRefreshToken(String token, User user) {
        refreshTokenService.save(token,user);
    }
}
