package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.CryptoRequest
import io.jsonwebtoken.security.SignatureAlgorithms
import io.jsonwebtoken.security.SignatureException
import io.jsonwebtoken.security.VerifySignatureRequest
import org.junit.Test

import javax.xml.crypto.dsig.spec.HMACParameterSpec
import java.nio.charset.StandardCharsets
import java.security.*
import java.security.spec.AlgorithmParameterSpec

import static org.easymock.EasyMock.createMock
import static org.junit.Assert.*

class AbstractSignatureAlgorithmTest {

    @Test
    void testCreateSignatureInstanceFailureNoProvider() {

        def alg = new TestAbstractSignatureAlgorithm() {
            @Override
            protected Signature getSignatureInstance(Provider provider) throws NoSuchAlgorithmException {
                throw new NoSuchAlgorithmException('message-here')
            }
        }

        try {
            alg.createSignatureInstance(null, null)
        } catch (SignatureException e) {
            assertEquals 'JWT signature algorithm \'test\' uses the JCA algorithm \'test\', which is not available in the current JVM. Try explicitly supplying a JCA Provider that supports the JCA algorithm name \'test\'. Cause: message-here', e.getMessage()
        }
    }

    @Test
    void testCreateSignatureInstanceFailureWithoutBouncyCastle() {
        def alg = new TestAbstractSignatureAlgorithm() {
            @Override
            protected Signature getSignatureInstance(Provider provider) throws NoSuchAlgorithmException {
                throw new NoSuchAlgorithmException('message-here')
            }

            @Override
            protected boolean isBouncyCastleAvailable() {
                return false
            }
        }

        try {
            alg.createSignatureInstance(null, null)
        } catch (SignatureException e) {
            assertEquals 'JWT signature algorithm \'test\' uses the JCA algorithm \'test\', which is not available in the current JVM. Try including BouncyCastle in the runtime classpath, or explicitly supplying a JCA Provider that supports the JCA algorithm name \'test\'. Cause: message-here', e.getMessage()
        }

    }

    @Test
    void testCreateSignatureInstanceFailureWithProvider() {

        def mockProvider = createMock(Provider)

        def alg = new TestAbstractSignatureAlgorithm() {
            @Override
            protected Signature getSignatureInstance(Provider provider) throws NoSuchAlgorithmException {
                throw new NoSuchAlgorithmException('message-here')
            }
        }

        try {
            alg.createSignatureInstance(mockProvider, null)
        } catch (SignatureException e) {
            assertEquals 'JWT signature algorithm \'test\' uses the JCA algorithm \'test\', which is not supported by the specified JCA Provider {EasyMock for class java.security.Provider}. Try explicitly supplying a JCA Provider that supports the JCA algorithm name \'test\'. Cause: message-here', e.getMessage()
        }
    }

    @Test
    void testCreateSignatureInstanceWithBadAlgParam() {
        def alg = new AbstractSignatureAlgorithm('RS256', 'SHA256withRSA') {
            @Override
            protected void validateKey(Key key, boolean signing) {
            }

            @Override
            protected byte[] doSign(CryptoRequest<byte[], Key> request) throws Exception {
                return new byte[0]
            }

            @Override
            protected void setParameter(Signature sig, AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException {
                throw new InvalidAlgorithmParameterException("whatevs")
            }
        }

        try {
            alg.createSignatureInstance(null, new HMACParameterSpec(256)) //not RSA at all
        } catch (SignatureException expected) {
            String msg = expected.getMessage()
            assertTrue msg.startsWith('Unsupported SHA256withRSA parameter {')
            assertTrue msg.endsWith('}: whatevs')
        }

    }

    @Test
    void testSignAndVerifyWithExplicitProvider() {
        Provider provider = Security.getProvider('BC')
        KeyPair pair = SignatureAlgorithms.RS256.generateKeyPair()
        byte[] data = 'foo'.getBytes(StandardCharsets.UTF_8)
        byte[] signature = SignatureAlgorithms.RS256.sign(new DefaultCryptoRequest<byte[], Key>(data, pair.getPrivate(), provider, null))
        assertTrue SignatureAlgorithms.RS256.verify(new DefaultVerifySignatureRequest(data, pair.getPublic(), provider, null, signature))
    }

    @Test
    void testSignFailsWithAnExternalException() {
        KeyPair pair = SignatureAlgorithms.RS256.generateKeyPair()
        def ise = new IllegalStateException('foo')
        def alg = new TestAbstractSignatureAlgorithm() {
            @Override
            protected byte[] doSign(CryptoRequest<byte[], Key> request) throws Exception {
                throw ise
            }
        }
        try {
            alg.sign(new DefaultCryptoRequest<byte[], Key>('foo'.getBytes(StandardCharsets.UTF_8), pair.getPrivate(), null, null))
        } catch (SignatureException e) {
            assertTrue e.getMessage().startsWith('Unable to compute test signature with JCA algorithm \'test\' using key {')
            assertTrue e.getMessage().endsWith('}: foo')
            assertSame ise, e.getCause()
        }
    }

    @Test
    void testVerifyFailsWithExternalException() {
        KeyPair pair = SignatureAlgorithms.RS256.generateKeyPair()
        def ise = new IllegalStateException('foo')
        def alg = new TestAbstractSignatureAlgorithm() {
            @Override
            protected boolean doVerify(VerifySignatureRequest request) throws Exception {
                throw ise
            }
        }
        def data = 'foo'.getBytes(StandardCharsets.UTF_8)
        try {
            byte[] signature = alg.sign(new DefaultCryptoRequest<byte[], Key>(data, pair.getPrivate(), null, null))
            alg.verify(new DefaultVerifySignatureRequest(data, pair.getPublic(), null, null, signature))
        } catch (SignatureException e) {
            assertTrue e.getMessage().startsWith('Unable to verify test signature with JCA algorithm \'test\' using key {')
            assertTrue e.getMessage().endsWith('}: foo')
            assertSame ise, e.getCause()
        }
    }

    class TestAbstractSignatureAlgorithm extends AbstractSignatureAlgorithm {

        def TestAbstractSignatureAlgorithm() {
            super('test', 'test')
        }

        @Override
        protected void validateKey(Key key, boolean signing) {
        }

        @Override
        protected byte[] doSign(CryptoRequest<byte[], Key> request) throws Exception {
            return new byte[1]
        }
    }
}
