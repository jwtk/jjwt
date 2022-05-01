package io.jsonwebtoken.impl.security


import org.junit.Test

import static org.junit.Assert.assertEquals

class DefaultJwkContextTest {

    @Test
    void testGetName() {
        def header = new DefaultJwkContext()
        assertEquals 'JWK', header.getName()
    }

    @Test
    void testGetNameWhenSecretKey() {
        def header = new DefaultJwkContext(DefaultSecretJwk.FIELDS)
        header.put('kty', 'oct')
        assertEquals 'Secret JWK', header.getName()
    }
}
