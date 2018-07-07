package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.codec.Decoder
import org.junit.Test
import static org.junit.Assert.*

class DefaultJwtSignatureValidatorTest {

    @Test //TODO: remove this before 1.0 since it tests a deprecated method
    @Deprecated
    void testDeprecatedTwoArgCtor() {

        def alg = SignatureAlgorithm.HS256
        def key = MacProvider.generateKey(alg)
        def validator = new DefaultJwtSignatureValidator(alg, key)

        assertNotNull validator.signatureValidator
        assertSame Decoder.BASE64URL, validator.base64UrlDecoder
    }

    @Test //TODO: remove this before 1.0 since it tests a deprecated method
    @Deprecated
    void testDeprecatedThreeArgCtor() {

        def alg = SignatureAlgorithm.HS256
        def key = MacProvider.generateKey(alg)
        def validator = new DefaultJwtSignatureValidator(DefaultSignatureValidatorFactory.INSTANCE, alg, key)

        assertNotNull validator.signatureValidator
        assertSame Decoder.BASE64URL, validator.base64UrlDecoder
    }
}
