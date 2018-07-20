package io.jsonwebtoken.impl

import io.jsonwebtoken.Jwt
import io.jsonwebtoken.Jwts
import org.junit.Test

import static org.junit.Assert.assertEquals

class DefaultJwtTest {

    @Test
    void testToString() {
        String compact = Jwts.builder().setHeaderParam('foo', 'bar').setAudience('jsmith').compact();
        Jwt jwt = Jwts.parser().parseClaimsJwt(compact);
        assertEquals 'header={foo=bar, alg=none},body={aud=jsmith}', jwt.toString()
    }

}
