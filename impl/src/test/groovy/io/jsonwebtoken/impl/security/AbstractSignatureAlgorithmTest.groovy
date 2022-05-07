package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.SignatureAlgorithms
import io.jsonwebtoken.security.SignatureException
import io.jsonwebtoken.security.SignatureRequest
import io.jsonwebtoken.security.VerifySignatureRequest
import org.junit.Test

import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.Provider
import java.security.Security

import static org.junit.Assert.assertSame
import static org.junit.Assert.assertTrue

class AbstractSignatureAlgorithmTest {

    @Test
    void testSignAndVerifyWithExplicitProvider() {
        Provider provider = Security.getProvider('BC')
        def pair = SignatureAlgorithms.RS256.keyPairBuilder().build() as io.jsonwebtoken.security.KeyPair
        byte[] data = 'foo'.getBytes(StandardCharsets.UTF_8)
        byte[] signature = SignatureAlgorithms.RS256.sign(new DefaultSignatureRequest<Key>(provider, null, data, pair.getPrivate()))
        assertTrue SignatureAlgorithms.RS256.verify(new DefaultVerifySignatureRequest(provider, null, data, pair.getPublic(), signature))
    }

    @Test
    void testSignFailsWithAnExternalException() {
        def pair = SignatureAlgorithms.RS256.keyPairBuilder().build() as io.jsonwebtoken.security.KeyPair
        def ise = new IllegalStateException('foo')
        def alg = new TestAbstractSignatureAlgorithm() {
            @Override
            protected byte[] doSign(SignatureRequest request) throws Exception {
                throw ise
            }
        }
        try {
            alg.sign(new DefaultSignatureRequest(null, null, 'foo'.getBytes(StandardCharsets.UTF_8), pair.getPrivate()))
        } catch (SignatureException e) {
            assertTrue e.getMessage().startsWith('Unable to compute test signature with JCA algorithm \'test\' using key {')
            assertTrue e.getMessage().endsWith('}: foo')
            assertSame ise, e.getCause()
        }
    }

    @Test
    void testVerifyFailsWithExternalException() {
        def pair = SignatureAlgorithms.RS256.keyPairBuilder().build() as io.jsonwebtoken.security.KeyPair
        def ise = new IllegalStateException('foo')
        def alg = new TestAbstractSignatureAlgorithm() {
            @Override
            protected boolean doVerify(VerifySignatureRequest request) throws Exception {
                throw ise
            }
        }
        def data = 'foo'.getBytes(StandardCharsets.UTF_8)
        try {
            byte[] signature = alg.sign(new DefaultSignatureRequest(null, null, data, pair.getPrivate()))
            alg.verify(new DefaultVerifySignatureRequest(null, null, data, pair.getPublic(), signature))
        } catch (SignatureException e) {
            assertTrue e.getMessage().startsWith('Unable to verify test signature with JCA algorithm \'test\' using key {')
            assertTrue e.getMessage().endsWith('}: foo')
            assertSame ise, e.getCause()
        }
    }

    class TestAbstractSignatureAlgorithm extends AbstractSignatureAlgorithm {

        TestAbstractSignatureAlgorithm() {
            super('test', 'test')
        }

        @Override
        protected void validateKey(Key key, boolean signing) {
        }

        @Override
        protected byte[] doSign(SignatureRequest request) throws Exception {
            return new byte[1]
        }
    }
}
