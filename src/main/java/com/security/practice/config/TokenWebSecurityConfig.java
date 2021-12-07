package com.security.practice.config;

import com.security.practice.filter.TokenAuthorizationFilter;
import com.security.practice.filter.TokenLoginFilter;
import com.security.practice.security.JWTTokenManager;
import com.security.practice.security.MD5PasswordEncoder;
import com.security.practice.security.TokenLogoutHandler;
import com.security.practice.security.UnAuthEntryPoint;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

public class TokenWebSecurityConfig extends WebSecurityConfigurerAdapter {

    private JWTTokenManager jwtTokenManager;
    private RedisTemplate redisTemplate;
    private MD5PasswordEncoder md5PasswordEncoder;
    private UserDetailsService userDetailsService;

    public TokenWebSecurityConfig(JWTTokenManager jwtTokenManager, RedisTemplate redisTemplate, MD5PasswordEncoder md5PasswordEncoder, UserDetailsService userDetailsService) {
        this.jwtTokenManager = jwtTokenManager;
        this.redisTemplate = redisTemplate;
        this.md5PasswordEncoder = md5PasswordEncoder;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.exceptionHandling().authenticationEntryPoint(new UnAuthEntryPoint())
                .and()
                .csrf().disable()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .logout().logoutUrl("api /logout").addLogoutHandler(new TokenLogoutHandler(jwtTokenManager, redisTemplate))
                .and()
                .addFilter(new TokenLoginFilter(authenticationManager(), jwtTokenManager, redisTemplate))
                .addFilter(new TokenAuthorizationFilter(authenticationManager(), jwtTokenManager, redisTemplate))
                .httpBasic();

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/api/login", "/api/register", "/api/logout", "/api/user/info");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(md5PasswordEncoder);
    }
}
