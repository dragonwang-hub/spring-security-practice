package com.security.practice.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JWTTokenManagerTest {

    private JWTTokenManager jwtTokenManager;

    @BeforeEach
    void setUp() {
        jwtTokenManager = new JWTTokenManager();
    }

    @Test
    void createToken() {
        String token = jwtTokenManager.generateJWTByUsername("test");
        System.out.println(token);
        assertNotNull(token);
    }

    @Test
    void parserToken() {
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIxIiwiaWF0IjoxNjM4NjcxNzA5LCJzdWIiOiJ0ZXN0In0.1awa6mpM_7IKM7vkmDgM-1fN6rKc1YVQzF1AqdFjiDU";
        String username = jwtTokenManager.parseUserNameFromJWT(jwt);
        System.out.println(username);
        assertNotNull(username);
    }
}
