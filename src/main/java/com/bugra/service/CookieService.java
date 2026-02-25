package com.bugra.service;

import com.bugra.exceptions.JwtException;
import com.bugra.security.JwtTokenProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Arrays;

import static com.bugra.enums.Token.access_token;
import static com.bugra.enums.Token.refresh_token;

@Service
public class CookieService {

    private final JwtTokenProvider tokenProvider;

    public CookieService(JwtTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;

    }

    public ResponseCookie generateHttpOnlyCookie(String cookieName, String cookieValue) {
        long expiration = Duration.ofHours(24).getSeconds();
        return ResponseCookie.from(cookieName, cookieValue)
                .secure(true)
                .sameSite("None")
                .httpOnly(true)
                .maxAge(expiration)
                .path("/")
                .build();
    }

    public void setJwtCookies(String accessToken, String refreshToken, HttpServletResponse response) {
        ResponseCookie accessCookie = generateHttpOnlyCookie(access_token.toString(),accessToken);
        ResponseCookie refreshCookie = generateHttpOnlyCookie(refresh_token.toString(),refreshToken);
        response.addHeader("Set-Cookie", accessCookie.toString());
        response.addHeader("Set-Cookie", refreshCookie.toString());
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
