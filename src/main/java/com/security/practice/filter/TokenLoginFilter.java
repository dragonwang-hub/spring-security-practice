package com.security.practice.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.practice.security.JWTTokenManager;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class TokenLoginFilter extends UsernamePasswordAuthenticationFilter {

    private JWTTokenManager jwtTokenManager;
    private RedisTemplate redisTemplate;

    public TokenLoginFilter(AuthenticationManager authenticationManager, JWTTokenManager jwtTokenManager, RedisTemplate redisTemplate) {
        super(authenticationManager);
        this.jwtTokenManager = jwtTokenManager;
        this.redisTemplate = redisTemplate;
        this.setPostOnly(false);
        this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
    }

    //  get username and password from form
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            User user = new ObjectMapper().readValue(request.getInputStream(), User.class);
            return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), new ArrayList<>()));
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("Error in parsing request body");
        }
    }

    // call after authenticated successfully
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) {
        User principal = (User) authResult.getPrincipal();
        String token = jwtTokenManager.generateJWTByUsername(principal.getUsername());
        redisTemplate.opsForValue().set(principal.getUsername(), principal.getAuthorities());
        response.setStatus(HttpServletResponse.SC_OK);
        response.addHeader("jwt-token", token);
    }

    // call after failed authentication
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
