package io.jsonwebtoken.all

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Header
import io.jsonwebtoken.Jwt
import io.jsonwebtoken.JwtParser
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import org.junit.Test

import static org.hamcrest.CoreMatchers.equalTo
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.CoreMatchers.notNullValue

/**
 * This test ensures that the included dependency are all that is needed to use JJWT.
 */
class BasicTest {

    @Test
    void basicUsageTest() {
        def key = Keys.secretKeyFor(SignatureAlgorithm.HS256)

        String token = Jwts.builder()
            .setSubject("test-user")
            .claim("test", "basicUsageTest")
            .signWith(key, SignatureAlgorithm.HS256)
            .compact()

        JwtParser parser = Jwts.parserBuilder()
            .setSigningKey(key)
            .build()

        Jwt<Header, Claims> result = parser.parseClaimsJws(token)
        assertThat result, notNullValue()
        assertThat result.getBody().getSubject(), equalTo("test-user")
        assertThat result.getBody().get("test", String), equalTo("basicUsageTest")
    }
}