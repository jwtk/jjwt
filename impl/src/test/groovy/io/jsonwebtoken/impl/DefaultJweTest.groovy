package io.jsonwebtoken.impl

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.EncryptionAlgorithms
import org.junit.Test

import static org.junit.Assert.assertEquals

class DefaultJweTest {

    @Test
    void testEqualsAndHashCode() {
        def alg = EncryptionAlgorithms.A128CBC_HS256
        def key = alg.keyBuilder().build()
        String compact = Jwts.jweBuilder().claim('foo', 'bar').encryptWith(alg).withKey(key).compact()
        def parser = Jwts.parserBuilder().decryptWith(key).build()
        def jwe1 = parser.parseClaimsJwe(compact)
        def jwe2 = parser.parseClaimsJwe(compact)
        assertEquals jwe1, jwe2
        assertEquals jwe1.hashCode(), jwe2.hashCode()
    }
}
