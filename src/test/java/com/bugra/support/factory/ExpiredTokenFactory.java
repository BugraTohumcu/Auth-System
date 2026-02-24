package com.bugra.support.factory;


import com.bugra.security.dto.TokenPayload;
import com.bugra.support.shared.TestConstants;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;

public class ExpiredTokenFactory {

    private static final String fakeSecret  = TestConstants.fake_secret;

    public static String generateExpiredToken(TokenPayload payload){
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("id",payload.id());
        claims.put("username",payload.username());
        claims.put("email", payload.email());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(payload.id())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() - Duration.ofSeconds(1).toMillis()))
                .signWith(getKey())
                .compact();
    }

    public static Key getKey(){
        byte[] keyBytes = Decoders.BASE64.decode(fakeSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
