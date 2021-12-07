package com.security.practice.filter;

import com.security.practice.security.JWTTokenManager;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;

public class TokenAuthorizationFilter extends BasicAuthenticationFilter {

    private JWTTokenManager jwtTokenManager;
    private RedisTemplate redisTemplate;

    public TokenAuthorizationFilter(AuthenticationManager authenticationManager, JWTTokenManager jwtTokenManager, RedisTemplate redisTemplate) {
        super(authenticationManager);
        this.jwtTokenManager = jwtTokenManager;
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // get user authorization info
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = getAuthenticationInfo(request);
        if (usernamePasswordAuthenticationToken != null) {
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        }
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthenticationInfo(HttpServletRequest request) {
        String token = request.getHeader("jwt-token");
        if (token != null) {
            String username = jwtTokenManager.parseUserNameFromJWT(token);
            Collection<GrantedAuthority> permissionList = (Collection<GrantedAuthority>) redisTemplate.opsForValue().get(username);
            return new UsernamePasswordAuthenticationToken(username, token, permissionList);
        }
        return null;
    }
}
