package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.EncryptionAlgorithmName
import io.jsonwebtoken.EncryptionAlgorithms
import io.jsonwebtoken.SignatureAlgorithm
import org.junit.Test

import static org.junit.Assert.*

class HmacAesEncryptionAlgorithmTest {

    @Test
    void testGetRequiredKeyLengthWithNullSignatureAlgorithm() {
        try {
            HmacAesEncryptionAlgorithm.getRequiredKeyLength(null)
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testGetRequiredKeyLengthWithInvalidSignatureAlgorithm() {
        try {
            HmacAesEncryptionAlgorithm.getRequiredKeyLength(SignatureAlgorithm.ES256)
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testGenerateHmacKeyBytesWithExactNumExpectedBytes() {

        int hmacKeySize = EncryptionAlgorithms.A128CBC_HS256.getRequiredKeyLength() / 2;

        def alg = new TestHmacAesEncryptionAlgorithm() {
            @Override
            protected byte[] generateHmacKeyBytes() {
                byte[] bytes = new byte[hmacKeySize]
                AbstractAesEncryptionAlgorithm.DEFAULT_RANDOM.nextBytes(bytes);
                return bytes;
            }
        }

        def skey = alg.generateKey()
        def key = skey.getEncoded()

        def plaintext = "Hello World! Nice to meet you!".getBytes("UTF-8")

        def request = EncryptionRequests.builder().setKey(key).setPlaintext(plaintext).build()

        def result = alg.encrypt(request);
        assert result instanceof AuthenticatedEncryptionResult

        def dreq = DecryptionRequests.builder()
                .setKey(key)
                .setInitializationValue(result.getInitializationValue())
                .setAuthenticationTag(result.getAuthenticationTag())
                .setCiphertext(result.getCiphertext())
                .build()

        byte[] decryptedPlaintextBytes = alg.decrypt(dreq)

        assertArrayEquals(plaintext, decryptedPlaintextBytes);
    }

    @Test
    void testGenerateHmacKeyBytesWithInsufficientNumExpectedBytes() {

        int hmacKeySize = EncryptionAlgorithms.A128CBC_HS256.getRequiredKeyLength() / 2;

        def alg = new TestHmacAesEncryptionAlgorithm() {
            @Override
            protected byte[] generateHmacKeyBytes() {
                byte[] bytes = new byte[hmacKeySize - 1]
                AbstractAesEncryptionAlgorithm.DEFAULT_RANDOM.nextBytes(bytes);
                return bytes;
            }
        }

        try {
            alg.generateKey()
            fail()
        } catch (CryptoException expected) {
        }
    }

    @Test
    void testDecryptWithInvalidTag() {

        def alg = EncryptionAlgorithms.A128CBC_HS256;

        def skey = alg.generateKey()
        def key = skey.getEncoded()

        def plaintext = "Hello World! Nice to meet you!".getBytes("UTF-8")

        def request = EncryptionRequests.builder().setKey(key).setPlaintext(plaintext).build()

        def result = alg.encrypt(request);
        assert result instanceof AuthenticatedEncryptionResult

        def realTag = result.getAuthenticationTag();

        //fake it:

        def fakeTag = new byte[realTag.length]
        AbstractAesEncryptionAlgorithm.DEFAULT_RANDOM.nextBytes(fakeTag)

        def dreq = DecryptionRequests.builder()
                .setKey(key)
                .setInitializationValue(result.getInitializationValue())
                .setAuthenticationTag(fakeTag)
                .setCiphertext(result.getCiphertext())
                .build()

        try {
            alg.decrypt(dreq)
            fail()
        } catch (CryptoException expected) {
        }
    }

    static class TestHmacAesEncryptionAlgorithm extends HmacAesEncryptionAlgorithm {
        TestHmacAesEncryptionAlgorithm() {
            super(EncryptionAlgorithmName.A128CBC_HS256.getValue(), SignatureAlgorithm.HS256);
        }
    }

}
