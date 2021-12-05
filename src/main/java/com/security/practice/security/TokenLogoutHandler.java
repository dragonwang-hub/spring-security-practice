package com.security.practice.security;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TokenLogoutHandler implements LogoutHandler {

    private JWTTokenManager jwtTokenManager;
    private RedisTemplate redisTemplate;


    public TokenLogoutHandler(JWTTokenManager jwtTokenManager, RedisTemplate redisTemplate) {
        this.jwtTokenManager = jwtTokenManager;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String jwtToken = request.getHeader("jwt-token");
        if (jwtToken != null) {
            jwtTokenManager.deleteToken(jwtToken);
            String username = jwtTokenManager.parseUserNameFromJWT(jwtToken);
            redisTemplate.delete(username);
        }
        response.setStatus(HttpServletResponse.SC_OK);
    }
}
