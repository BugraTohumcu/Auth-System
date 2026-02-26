package com.bugra.service;

import com.bugra.exceptions.TokenNotFoundException;
import com.bugra.exceptions.TokenRevokedException;
import com.bugra.model.RefreshToken;
import com.bugra.model.User;
import com.bugra.repo.RefreshTokenRepo;
import com.bugra.security.JwtTokenProvider;
import com.bugra.security.dto.TokenPayload;
import com.bugra.security.dto.TokensRefreshed;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepo refreshTokenRepo;
    private final JwtTokenProvider jwtTokenProvider;

    public RefreshTokenService(RefreshTokenRepo refreshTokenRepo, JwtTokenProvider jwtTokenProvider) {
        this.refreshTokenRepo = refreshTokenRepo;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Transactional()
    public void save(String token, User user) {
        RefreshToken refreshToken = new RefreshToken();
        Instant expiresAt = Instant.now().plus(7, ChronoUnit.DAYS);

        refreshToken.setJti(jwtTokenProvider.extractJti(token));
        refreshToken.setExpires(expiresAt);
        refreshToken.setUser(user);
        refreshTokenRepo.save(refreshToken);
    }

    @Transactional()
    public void revoke(String refreshToken) {
        String jti = jwtTokenProvider.extractJti(refreshToken);
        int modified = refreshTokenRepo.revokeTokenByJti(jti);
        if(modified == 0) {
            throw  new TokenNotFoundException("Refresh token not found");
        }
    }

    @Transactional()
    public TokensRefreshed refreshTokens(String refreshToken, User user) {
        String jti = jwtTokenProvider.extractJti(refreshToken);
        if(!refreshTokenRepo.isTokenRevoked(jti)){
            throw new TokenRevokedException("Refresh token already revoked");
        }

        TokenPayload payload = TokenPayload.fromUser(user);
        String newAccessToken = jwtTokenProvider.generateAccessToken(payload);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(payload);

        TokensRefreshed tokens = new TokensRefreshed(newAccessToken, newRefreshToken);
        save(newRefreshToken,user);
        return tokens;
    }
}
