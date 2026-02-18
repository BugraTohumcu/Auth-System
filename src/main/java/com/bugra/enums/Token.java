package com.bugra.enums;

public enum Token {
    access_token("access_token"),
    refresh_token("refresh_token");

    private String token;
    Token(String token) {
        this.token = token;
    }
    @Override
    public String toString() {
        return token.toLowerCase();
    }

}
