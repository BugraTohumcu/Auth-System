package com.bugra.enums;

import lombok.Getter;

@Getter
public enum EndPoints {
    LOGIN("/auth/login"),
    REGISTER("/auth/register"),
    REFRESH("/auth/refresh_token");


    private final String path;

    EndPoints(String path){
         this.path = path;
    }
}
