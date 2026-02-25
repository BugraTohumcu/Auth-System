package com.bugra.facade;

import com.bugra.model.User;
import com.bugra.security.dto.TokenPayload;
import com.bugra.service.CookieService;
import com.bugra.service.JwtService;
import com.bugra.enums.Token;
import com.bugra.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;

@Service
public class AuthFacade {

    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenService refreshTokenService;

    public AuthFacade(JwtService jwtService, CookieService cookieService, RefreshTokenService refreshTokenService) {
        this.jwtService = jwtService;
        this.cookieService = cookieService;
        this.refreshTokenService = refreshTokenService;
    }

    public void saveTokenAndSetCookie(User user, HttpServletResponse response) {
        TokenPayload payload = TokenPayload.fromUser(user);
        String refreshToken = jwtService.createToken(Token.refresh_token, payload);
        String accessToken = jwtService.createToken(Token.access_token, payload);
        refreshTokenService.save(refreshToken, user);
        cookieService.setJwtCookies(accessToken, refreshToken, response);
    }
}
