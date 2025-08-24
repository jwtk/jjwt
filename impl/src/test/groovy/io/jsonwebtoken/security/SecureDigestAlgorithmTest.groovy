package io.jsonwebtoken.security

import io.jsonwebtoken.Jwts
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.assertTrue

class SecureDigestAlgorithmTest {

    // only need one each of mac algorithm and signature algorithm - no need to take time for key generation
    static final def algs = [Jwts.SIG.HS256, Jwts.SIG.ES256]

    @Test
    void testRoundtrip() {

        final msg = 'hello world'
        final is = new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8))

        algs.each { alg ->
            def skey
            def vkey

            if (alg instanceof KeyPairBuilderSupplier) {
                def pair = alg.keyPair().build()
                skey = pair.getPrivate()
                vkey = pair.getPublic()
            } else {
                skey = vkey = alg.key().build()
            }

            byte[] digest = alg.digest(skey, is)
            is.reset()
            assertTrue alg.verify(vkey, is, digest)
            is.reset()
        }
    }
}
