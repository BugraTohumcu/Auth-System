package com.bugra.facade;

import com.bugra.model.User;
import com.bugra.security.dto.TokenPayload;
import com.bugra.service.JwtService;
import com.bugra.enums.Token;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;

@Service
public class AuthFacade {

    private final JwtService jwtService;

    public AuthFacade(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    public void saveTokenAndSetCookie(User user, HttpServletResponse response) {
        TokenPayload payload = TokenPayload.fromUser(user);
        String refreshToken = jwtService.createToken(Token.refresh_token, payload);
        String accessToken = jwtService.createToken(Token.access_token, payload);
        jwtService.saveRefreshToken(refreshToken, user);
        jwtService.setJwtCookies(accessToken, refreshToken, response);
    }
}
