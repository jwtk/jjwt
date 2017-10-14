package io.jsonwebtoken.impl.crypto

import org.junit.Test

import java.security.SecureRandom

import static org.junit.Assert.*

class AbstractAesEncryptionAlgorithmTest {

    @Test
    void testConstructorWithIvLargerThanAesBlockSize() {

        try {
            new TestAesEncryptionAlgorithm('foo', 'foo', 17, 16);
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testConstructorWithoutIvLength() {

        try {
            new TestAesEncryptionAlgorithm('foo', 'foo', 0, 16);
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testConstructorWithoutRequiredKeyLength() {

        try {
            new TestAesEncryptionAlgorithm('foo', 'foo', 16, 0);
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testDoEncryptFailure() {

        def alg = new TestAesEncryptionAlgorithm('foo', 'foo', 16, 16) {
            @Override
            protected EncryptionResult doEncrypt(EncryptionRequest req) throws Exception {
                throw new IllegalArgumentException('broken')
            }
        }

        def req = EncryptionRequests.builder()
                .setAdditionalAuthenticatedData('foo'.getBytes())
                .setInitializationValue('iv'.getBytes())
                .setKey(alg.generateKey().getEncoded())
                .setPlaintext('bar'.getBytes())
                .build();

        try {
            alg.encrypt(req)
        } catch (CryptoException expected) {
            assertTrue expected.getCause() instanceof IllegalArgumentException
            assertTrue expected.getCause().getMessage().equals('broken')
        }
    }

    @Test
    void testAssertKeyLength() {

        def requiredKeyLength = 16

        def alg = new TestAesEncryptionAlgorithm('foo', 'foo', 16, requiredKeyLength)

        byte[] bytes = new byte[requiredKeyLength + 1] //not same as requiredKeyLength, but it should be
        AbstractAesEncryptionAlgorithm.DEFAULT_RANDOM.nextBytes(bytes)

        try {
            alg.assertKeyLength(bytes)
            fail()
        } catch (CryptoException expected) {
        }
    }

    @Test
    void testGetSecureRandomWhenRequestHasSpecifiedASecureRandom() {

        def alg = new TestAesEncryptionAlgorithm('foo', 'foo', 16, 16)

        def secureRandom = new SecureRandom()

        def req = EncryptionRequests.builder()
                .setAdditionalAuthenticatedData('foo'.getBytes())
                .setInitializationValue('iv'.getBytes())
                .setKey(alg.generateKey().getEncoded())
                .setPlaintext('bar'.getBytes())
                .setSecureRandom(secureRandom)
                .build();

        def returnedSecureRandom = alg.getSecureRandom(req)

        assertSame(secureRandom, returnedSecureRandom)
    }

    static class TestAesEncryptionAlgorithm extends AbstractAesEncryptionAlgorithm {

        TestAesEncryptionAlgorithm(String name, String transformationString, int generatedIvLength, int requiredKeyLength) {
            super(name, transformationString, generatedIvLength, requiredKeyLength)
        }

        @Override
        protected EncryptionResult doEncrypt(EncryptionRequest req) throws Exception {
            return null
        }

        @Override
        protected byte[] doDecrypt(DecryptionRequest req) throws Exception {
            return new byte[0]
        }
    }

}
