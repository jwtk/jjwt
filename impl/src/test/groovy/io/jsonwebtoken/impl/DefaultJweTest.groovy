package io.jsonwebtoken.impl

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.EncryptionAlgorithms
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotEquals

class DefaultJweTest {

    @Test
    void testEqualsAndHashCode() {
        def alg = EncryptionAlgorithms.A128CBC_HS256
        def key = alg.keyBuilder().build()
        String compact = Jwts.builder().claim('foo', 'bar').encryptWith(alg, key).compact()
        def parser = Jwts.parserBuilder().decryptWith(key).build()
        def jwe1 = parser.parseClaimsJwe(compact)
        def jwe2 = parser.parseClaimsJwe(compact)
        assertNotEquals jwe1, 'hello' as String
        assertEquals jwe1, jwe1
        assertEquals jwe2, jwe2
        assertEquals jwe1, jwe2
        assertEquals jwe1.hashCode(), jwe2.hashCode()
    }
}
