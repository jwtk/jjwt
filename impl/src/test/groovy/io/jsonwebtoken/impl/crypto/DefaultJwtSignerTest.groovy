package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.Keys
import org.junit.Test

import static org.junit.Assert.assertNotNull
import static org.junit.Assert.assertSame

class DefaultJwtSignerTest {

    @Test
    //TODO: remove this before 1.0 since it tests a deprecated method
    @Deprecated
    //remove just before 1.0.0 release
    void testDeprecatedTwoArgCtor() {

        def alg = SignatureAlgorithm.HS256
        def key = Keys.secretKeyFor(alg)
        def signer = new DefaultJwtSigner(alg, key)

        assertNotNull signer.signer
        assertSame Encoders.BASE64URL, signer.base64UrlEncoder
    }

    @Test
    //TODO: remove this before 1.0 since it tests a deprecated method
    @Deprecated
    //remove just before 1.0.0 release
    void testDeprecatedThreeArgCtor() {

        def alg = SignatureAlgorithm.HS256
        def key = Keys.secretKeyFor(alg)
        def signer = new DefaultJwtSigner(DefaultSignerFactory.INSTANCE, alg, key)

        assertNotNull signer.signer
        assertSame Encoders.BASE64URL, signer.base64UrlEncoder
    }
}
