package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.CryptoException
import io.jsonwebtoken.security.PayloadSupplier
import io.jsonwebtoken.security.CryptoRequest
import org.junit.Test

import javax.crypto.spec.SecretKeySpec

import static org.junit.Assert.assertSame

class AbstractEncryptionAlgorithmTest {

    @Test
    void testDoEncryptCryptoExceptionPropagates() {
        final CryptoException expected = new CryptoException("foo")

        AbstractEncryptionAlgorithm alg = new AbstractEncryptionAlgorithm('foo', 'foo') {
            protected PayloadSupplier<byte[]> doEncrypt(CryptoRequest cryptoRequest) throws Exception {
                throw expected
            }
            protected byte[] doDecrypt(CryptoRequest cryptoRequest) throws Exception {
                throw new IllegalStateException("should not be called")
            }
        }

        try {
            alg.encrypt(new DefaultSymmetricAeadRequest(null, null, new byte[1], new SecretKeySpec(new byte[1], 'AES')))
        } catch (CryptoException thrown) {
            assertSame expected, thrown
        }
    }

    @Test
    void testDecryptWithNonCryptoExceptionThrowsCryptoException() {
        final IllegalStateException expected = new IllegalStateException("decrypt")

        AbstractEncryptionAlgorithm alg = new AbstractEncryptionAlgorithm('foo', 'foo') {
            protected PayloadSupplier<byte[]> doEncrypt(CryptoRequest cryptoRequest) throws Exception {
                throw new IllegalStateException("should not be called")
            }
            protected byte[] doDecrypt(CryptoRequest cryptoRequest) throws Exception {
                throw expected
            }
        }

        try {
            alg.decrypt(new DefaultSymmetricAeadResult(null, null, new byte[1], new SecretKeySpec(new byte[1], 'AES'), null, new byte[1], new byte[1]))
        } catch (CryptoException thrown) {
            assertSame expected, thrown.getCause()
        }
    }

}
