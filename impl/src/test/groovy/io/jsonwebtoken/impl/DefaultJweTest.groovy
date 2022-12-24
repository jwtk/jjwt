package io.jsonwebtoken.impl

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.EncryptionAlgorithms
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotEquals

class DefaultJweTest {

    @Test
    void testToString() {
        def alg = EncryptionAlgorithms.A128CBC_HS256
        def key = alg.keyBuilder().build()
        String compact = Jwts.builder().claim('foo', 'bar').encryptWith(key, alg).compact()
        def jwe = Jwts.parserBuilder().decryptWith(key).build().parseClaimsJwe(compact)
        String encodedIv = Encoders.BASE64URL.encode(jwe.initializationVector)
        String encodedTag = Encoders.BASE64URL.encode(jwe.aadTag)
        String expected = "header={alg=dir, enc=A128CBC-HS256},payload={foo=bar},iv=$encodedIv,tag=$encodedTag"
        assertEquals expected, jwe.toString()
    }

    @Test
    void testEqualsAndHashCode() {
        def alg = EncryptionAlgorithms.A128CBC_HS256
        def key = alg.keyBuilder().build()
        String compact = Jwts.builder().claim('foo', 'bar').encryptWith(key, alg).compact()
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
