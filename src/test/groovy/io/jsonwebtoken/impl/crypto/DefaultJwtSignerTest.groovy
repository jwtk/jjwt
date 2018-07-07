package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.codec.Encoder
import org.junit.Test

import static org.junit.Assert.*

class DefaultJwtSignerTest {

    @Test //TODO: remove this before 1.0 since it tests a deprecated method
    @Deprecated //remove just before 1.0.0 release
    void testDeprecatedTwoArgCtor() {

        def alg = SignatureAlgorithm.HS256
        def key = MacProvider.generateKey(alg)
        def signer = new DefaultJwtSigner(alg, key)

        assertNotNull signer.signer
        assertSame Encoder.BASE64URL, signer.base64UrlEncoder
    }

    @Test //TODO: remove this before 1.0 since it tests a deprecated method
    @Deprecated //remove just before 1.0.0 release
    void testDeprecatedThreeArgCtor() {

        def alg = SignatureAlgorithm.HS256
        def key = MacProvider.generateKey(alg)
        def signer = new DefaultJwtSigner(DefaultSignerFactory.INSTANCE, alg, key)

        assertNotNull signer.signer
        assertSame Encoder.BASE64URL, signer.base64UrlEncoder
    }
}
