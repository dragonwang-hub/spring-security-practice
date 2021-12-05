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
}
