package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.*
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class JwkConverterTest {

    @Test
    void testJwkClassTypeString() {
        assertEquals 'JWK', JwkConverter.typeString(Jwk.class)
    }

    @Test
    void testSecretJwkClassTypeString() {
        assertEquals 'Secret JWK', JwkConverter.typeString(SecretJwk.class)
    }

    @Test
    void testSecretJwkTypeString() {
        def jwk = Jwks.builder().forKey(TestKeys.HS256).build()
        assertEquals 'Secret JWK', JwkConverter.typeString(jwk)
    }

    @Test
    void testPublicJwkClassTypeString() {
        assertEquals 'Public JWK', JwkConverter.typeString(PublicJwk.class)
    }

    @Test
    void testEcPublicJwkClassTypeString() {
        assertEquals 'EC Public JWK', JwkConverter.typeString(EcPublicJwk.class)
    }

    @Test
    void testRsaPublicJwkClassTypeString() {
        assertEquals 'RSA Public JWK', JwkConverter.typeString(RsaPublicJwk.class)
    }

    @Test
    void testPrivateJwkClassTypeString() {
        assertEquals 'Private JWK', JwkConverter.typeString(PrivateJwk.class)
    }

    @Test
    void testEcPrivateJwkClassTypeString() {
        assertEquals 'EC Private JWK', JwkConverter.typeString(EcPrivateJwk.class)
    }

    @Test
    void testRsaPrivateJwkClassTypeString() {
        assertEquals 'RSA Private JWK', JwkConverter.typeString(RsaPrivateJwk.class)
    }

    @Test
    void testPrivateJwk() {
        JwkConverter<PrivateJwk> converter = new JwkConverter<>(PrivateJwk.class)
        def jwk = Jwks.builder().forKey(TestKeys.HS256).build()
        try {
            converter.applyFrom(jwk)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Value must be a Private JWK, not a Secret JWK."
            assertEquals msg, expected.getMessage()
        }
    }

}
