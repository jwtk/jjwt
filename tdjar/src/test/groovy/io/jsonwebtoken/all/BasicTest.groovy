package io.jsonwebtoken.all

import io.jsonwebtoken.*
import io.jsonwebtoken.security.Keys
import org.junit.Test

import static org.hamcrest.CoreMatchers.equalTo
import static org.hamcrest.CoreMatchers.notNullValue
import static org.hamcrest.MatcherAssert.assertThat

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
