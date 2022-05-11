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

    @Test
    void testGStringPrintsRedactedValues() {

        // DO NOT REMOVE THIS METHOD: IT IS CRITICAL TO ENSURE GROOVY STRINGS DO NOT LEAK SECRET/PRIVATE KEY MATERIAL
        // If you still believe it should be removed, discuss with the JJWT dev team first.

        def header = new DefaultJwkContext(DefaultSecretJwk.FIELDS)
        header.put('kty', 'oct')
        header.put('k', 'test')
        String s = '[kty:oct, k:<redacted>]'
        assertEquals "$s", "$header"
    }

    @Test
    void testGStringToStringPrintsRedactedValues() {
        def header = new DefaultJwkContext(DefaultSecretJwk.FIELDS)
        header.put('kty', 'oct')
        header.put('k', 'test')
        String s = '{kty=oct, k=<redacted>}'
        assertEquals "$s", "${header.toString()}"
    }
}
