package com.bugra.service;

import com.bugra.exceptions.JwtException;
import com.bugra.security.JwtTokenProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Arrays;

import static com.bugra.enums.Token.access_token;

@Service
public class CookieService {

    private final JwtTokenProvider tokenProvider;

    public CookieService(JwtTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;

    }

    public ResponseCookie setTokensInCookies(String cookieName, String cookieValue) {
        long expiration = Duration.ofHours(24).getSeconds();
        return ResponseCookie.from(cookieName, cookieValue)
                .secure(true)
                .sameSite("None")
                .httpOnly(true)
                .maxAge(expiration)
                .path("/")
                .build();
    }

    public String getUserIdFromCookies(HttpServletRequest request) {
        String token = extractTokenFromCookies(access_token.toString(), request);
        return tokenProvider.extractId(token);
    }

    public String extractTokenFromCookies(String tokenName ,HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if(cookies == null) throw new JwtException("Cookies not found", 404);
        return Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals(tokenName))
                .map(Cookie::getValue)
                .findFirst()
                .orElseThrow(() -> new JwtException("Token not found!", 404));

    }
}
