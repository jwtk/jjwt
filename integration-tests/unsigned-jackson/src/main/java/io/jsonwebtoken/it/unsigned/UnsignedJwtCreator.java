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
                .setSubject("jjwt")
                .setId("jjwt-0")
                .setIssuedAt(Date.from(Instant.now()))
                .setNotBefore(Date.from(Instant.now()))
                .compact();
    }

    public Jwt<Header, Claims> read(String jwt) {
        final JwtParser jwtParser = Jwts.parserBuilder()
                .requireSubject("jjwt")
                .build();

        return jwtParser.parseClaimsJwt(jwt);
    }
}
