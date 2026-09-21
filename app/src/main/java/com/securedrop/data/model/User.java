package com.securedrop.data.model;

public class User {
    public final String id;
    public final String username;
    public final String email;

    public User(String id, String username, String email) {
        this.id = id;
        this.username = username;
        this.email = email;
    }
}
