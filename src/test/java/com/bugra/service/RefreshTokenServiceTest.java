package com.bugra.service;

import com.bugra.exceptions.TokenRevokedException;
import com.bugra.model.User;
import com.bugra.repo.RefreshTokenRepo;
import com.bugra.security.JwtTokenProvider;
import com.bugra.security.dto.TokenPayload;
import com.bugra.security.dto.TokensRefreshed;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.AssertionsForClassTypes.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepo refreshTokenRepo;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @InjectMocks
    private RefreshTokenService refreshTokenService;

    private final String refreshToken = "eyJhbGciOiJIUzI1NiJ9";
    private final String jti = "jti-123";
    private User mockUser;

    @BeforeEach
    void setUp(){
        mockUser = new User();
        mockUser.setEmail("test@gmail.com");
    }

    @Test
    void shouldReturnTokens_whenTokenIsValid() {

        //Arrange
        when(jwtTokenProvider.extractJti(refreshToken)).thenReturn(jti);
        when(refreshTokenRepo.isTokenRevoked(jti)).thenReturn(true);
        when(jwtTokenProvider.generateAccessToken(any(TokenPayload.class))).thenReturn("new.access");
        when(jwtTokenProvider.generateRefreshToken(any(TokenPayload.class))).thenReturn("new.refresh");
        when(jwtTokenProvider.extractJti("new.refresh")).thenReturn("new-jti-456");

        //Act
        TokensRefreshed result = refreshTokenService.refreshTokens(refreshToken,mockUser);

        assertThat(result).isNotNull();
        assertThat(result.access_token()).isEqualTo("new.access");
        assertThat(result.refresh_token()).isEqualTo("new.refresh");

    }
    @Test
    void shouldSaveTokens_whenTokenIsValid() {

        //Arrange
        when(jwtTokenProvider.extractJti(refreshToken)).thenReturn(jti);
        when(refreshTokenRepo.isTokenRevoked(jti)).thenReturn(true);
        when(jwtTokenProvider.generateAccessToken(any(TokenPayload.class))).thenReturn("new.access");
        when(jwtTokenProvider.generateRefreshToken(any(TokenPayload.class))).thenReturn("new.refresh");
        when(jwtTokenProvider.extractJti("new.refresh")).thenReturn("new-jti-456");

        //Act
        refreshTokenService.refreshTokens(refreshToken,mockUser);

        verify(refreshTokenRepo, times(1)).save(any());

    }

    @Test
    void shouldNotSaveToken_whenTokenInvalid() {
        // arrange
        when(jwtTokenProvider.extractJti(refreshToken)).thenReturn(jti);
        when(refreshTokenRepo.isTokenRevoked(jti)).thenReturn(false);

        // act & assert
        assertThatThrownBy(() -> refreshTokenService.refreshTokens(refreshToken,mockUser))
                .isInstanceOf(TokenRevokedException.class)
                .hasMessageContaining("already revoked");

    }
}