package com.bugra.enums;

public enum Role {
    User("USER"),
    Admin("ADMIN");

    @Override
    public String toString() {
        return role.toUpperCase();
    }

    private final String role;
    Role(String role) {
        this.role = role;
    }
}
