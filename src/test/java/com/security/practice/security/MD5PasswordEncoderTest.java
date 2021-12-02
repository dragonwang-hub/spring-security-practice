package com.security.practice.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MD5PasswordEncoderTest {

    private MD5PasswordEncoder encoder = new MD5PasswordEncoder();

    @BeforeEach
    void setUp() {
    }

    @Test
    void encode() {
        assertEquals("e10adc3949ba59abbe56e057f20f883e", encoder.encode("123456"));
    }

    @Test
    void matches() {
        assertTrue(encoder.matches("123456", "e10adc3949ba59abbe56e057f20f883e"));
    }
}
