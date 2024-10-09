package io.jsonwebtoken.it.unsigned;

import io.jsonwebtoken.*;

import java.time.Instant;
import java.util.Date;
import java.util.List;

public class UnsignedJwtCreator {

    public UnsignedJwtCreator() {
        // explicit
    }

    public String create() {
        return Jwts.builder()
                .claim("roles", List.of("admin"))
                .subject("jjwt")
                .id("jjwt-0")
                .issuedAt(Date.from(Instant.now()))
                .notBefore(Date.from(Instant.now()))
                .compact();
    }

    public Jwt<Header, Claims> read(String jwt) {
        final JwtParser jwtParser = Jwts.parser()
                .unsecured()
                .requireSubject("jjwt")
                .build();

        return jwtParser.parseUnsecuredClaims(jwt);
    }
}
