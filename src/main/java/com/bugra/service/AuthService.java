package com.bugra.service;

import com.bugra.model.User;
import com.bugra.security.dto.TokensRefreshed;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;

import static com.bugra.enums.Token.refresh_token;

@Service
public class AuthService {

    private final RefreshTokenService refreshTokenService;
    private final CookieService cookieService;

    public AuthService(RefreshTokenService refreshTokenService, CookieService cookieService) {
        this.refreshTokenService = refreshTokenService;
        this.cookieService = cookieService;
    }

    public void refreshToken(User user, HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = cookieService.extractTokenFromCookies(refresh_token.toString(), request);
        refreshTokenService.revoke(refreshToken);
        TokensRefreshed tokens = refreshTokenService.refreshTokens(refreshToken ,user);
        cookieService.setJwtCookies(tokens.access_token(), tokens.refresh_token(), response);
    }
}
