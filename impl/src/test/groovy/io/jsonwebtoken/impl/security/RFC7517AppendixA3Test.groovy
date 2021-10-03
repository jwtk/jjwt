package io.jsonwebtoken.impl.security

import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.SecretJwk
import org.junit.Test

import javax.crypto.SecretKey

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotNull

/**
 * https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.3
 */
class RFC7517AppendixA3Test {

    private static final String encode(SecretKey key) {
        return Encoders.BASE64URL.encode(key.getEncoded())
    }

    private static final List<Map<String, String>> keys = [
            [
                    "kty": "oct",
                    "alg": "A128KW",
                    "k"  : "GawgguFyGrWKav7AX4VKUg"
            ],
            [
                    "kty": "oct",
                    "k"  : "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
                    "kid": "HMAC key used in JWS spec Appendix A.1 example"
            ]
    ]

    @Test
    void test() { // asserts we can parse and verify RFC values

        def m = keys[0]
        SecretJwk jwk = Jwks.builder().putAll(m).build() as SecretJwk
        def key = jwk.toKey() as SecretKey
        assertNotNull key
        assertEquals m.size(), jwk.size()
        assertEquals m.kty, jwk.getType()
        assertEquals m.alg, jwk.getAlgorithm()
        assertEquals m.k, jwk.get('k')
        assertEquals m.k, encode(key)

        m = keys[1]
        jwk = Jwks.builder().putAll(m).build() as SecretJwk
        key = jwk.toKey() as SecretKey
        assertNotNull key
        assertEquals m.size(), jwk.size()
        assertEquals m.kty, jwk.getType()
        assertEquals m.k, jwk.get('k')
        assertEquals m.k, encode(key)
        assertEquals m.kid, jwk.getId()
    }
}
