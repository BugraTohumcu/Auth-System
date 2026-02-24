package com.bugra.security;

import com.bugra.security.dto.TokenPayload;
import com.bugra.support.factory.ExpiredTokenFactory;
import com.bugra.support.shared.TestConstants;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;



class JwtTokenProviderTest {

    private final String fakeSecret;
    private final JwtTokenProvider tokenProvider;

    JwtTokenProviderTest(){
        fakeSecret = TestConstants.fake_secret;
        tokenProvider = new JwtTokenProvider();
        ReflectionTestUtils.setField(tokenProvider, "secret",
                fakeSecret);
    }

    @Test
    void isTokenExpired() {

        TokenPayload mockPayload = TokenPayload.builder()
                .id("1312")
                .email("sas@gmail.com")
                .username("necmi")
                .createdAt(new Date())
                .build();
        String token = ExpiredTokenFactory.generateExpiredToken(mockPayload);

        assertTrue(tokenProvider.isTokenExpired(token));
    }
}