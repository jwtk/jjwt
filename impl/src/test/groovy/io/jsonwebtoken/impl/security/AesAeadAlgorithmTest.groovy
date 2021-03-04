package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.CryptoException
import io.jsonwebtoken.security.SymmetricAeadDecryptionRequest
import io.jsonwebtoken.security.SymmetricAeadEncryptionResult
import io.jsonwebtoken.security.SymmetricAeadRequest
import org.junit.Test

import javax.crypto.spec.SecretKeySpec

import static org.junit.Assert.assertEquals

class AesAeadAlgorithmTest {

    @Test
    void testEnsureInitializationVectorWithNonIvRequest() {

        def alg = new AesAeadAlgorithm('test', 'AES', 128, 128) {
            @Override
            protected SymmetricAeadEncryptionResult doEncrypt(SymmetricAeadRequest request) throws Exception {
                return null
            }

            @Override
            protected byte[] doDecrypt(SymmetricAeadDecryptionRequest symmetricAeadDecryptionRequest) throws Exception {
                return new byte[0]
            }
        }

        byte[] data = new byte[1]
        def key = new SecretKeySpec(data, 'AES')

        def request = new DefaultCryptoRequest(null, null, data, key)
        byte[] iv = alg.ensureInitializationVector(request)
        assertEquals 16, iv.length //no iv supplied in the request, but one was created anyway
    }

    @Test
    void testAssertIvLengthIncorrect() {

        def alg = new AesAeadAlgorithm('test', 'AES', 128, 128) {
            @Override
            protected SymmetricAeadEncryptionResult doEncrypt(SymmetricAeadRequest request) throws Exception {
                return null
            }

            @Override
            protected byte[] doDecrypt(SymmetricAeadDecryptionRequest symmetricAeadDecryptionRequest) throws Exception {
                return new byte[0]
            }
        }

        byte[] iv = new byte[8] // should be 16
        try {
            alg.assertIvLength(iv)
        } catch (CryptoException expected) {
            String msg = 'The test algorithm requires initialization vectors with a length of 128 bits (16 bytes).  ' +
                    'The provided initialization vector has a length of 64 bits (8 bytes).'
            assertEquals msg, expected.getMessage()
        }
    }
}
