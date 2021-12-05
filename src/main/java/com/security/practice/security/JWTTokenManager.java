package com.security.practice.security;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;

public class JWTTokenManager {

    //The JWT signature algorithm we will be using to sign the token
    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
    long currentMillis = System.currentTimeMillis();
    Date now = new Date(currentMillis);

    //We will sign our JWT with our ApiKey secret
    String apiKey = "fake.apiKey.getSecret()";
    byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(apiKey);
    Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

    long expirationTime = 60 * 60 * 24;

    public String generateJWTByUsername(String username) {
        JwtBuilder jwtBuilder = Jwts.builder()
                .setId("1")
                .setIssuedAt(now)
                .setExpiration(new Date(currentMillis + expirationTime))
                .setSubject(username)
                .signWith(signatureAlgorithm, signingKey);

        //Builds the JWT and serializes it to a compact, URL-safe string
        return jwtBuilder.compact();
    }

    public String parseUserNameFromJWT(String jwt) {
        Claims claims = Jwts.parser().setSigningKey(apiKeySecretBytes).parseClaimsJws(jwt).getBody();
        return claims.getSubject();
    }
}
