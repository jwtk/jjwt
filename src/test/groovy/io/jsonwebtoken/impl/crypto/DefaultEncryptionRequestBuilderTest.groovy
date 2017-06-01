package io.jsonwebtoken.impl.crypto

import org.junit.Test

import static org.junit.Assert.*

class DefaultEncryptionRequestBuilderTest {

    private byte[] generateData() {
        byte[] data = new byte[32];
        new Random().nextBytes(data) //does not need to be secure for this test
        return data;
    }

    @Test
    void testWithAad() {

        def key = generateData()
        def iv = generateData()
        def plaintext = generateData()
        def aad = generateData()

        def req = new DefaultEncryptionRequestBuilder()
                .setKey(key).setInitializationVector(iv).setPlaintext(plaintext).setAdditionalAuthenticatedData(aad)
                .build()

        assertTrue req instanceof DefaultAuthenticatedEncryptionRequest
        assertSame key, req.getKey()
        assertSame iv, req.getInitializationVector()
        assertSame plaintext, req.getPlaintext()
        assertSame aad, req.getAssociatedData()
    }

    @Test
    void testWithoutAad() {

        def key = generateData()
        def iv = generateData()
        def plaintext = generateData()

        def req = new DefaultEncryptionRequestBuilder()
                .setKey(key).setInitializationVector(iv).setPlaintext(plaintext).build()

        assertTrue req instanceof DefaultEncryptionRequest
        assertSame key, req.getKey()
        assertSame iv, req.getInitializationVector()
        assertSame plaintext, req.getPlaintext()
    }

    @Test
    void testSetInitializationVectorWithEmptyArray() {
        def b = new DefaultEncryptionRequestBuilder().setInitializationVector(new byte[0])
        assertNull b.iv
    }

    @Test
    void testSetKeyWithEmptyArray() {
        def b = new DefaultEncryptionRequestBuilder().setKey(new byte[0])
        assertNull b.key
    }

    @Test
    void testSetAdditionalAuthenticatedDataWithEmptyArray() {
        def b = new DefaultEncryptionRequestBuilder().setAdditionalAuthenticatedData(new byte[0])
        assertNull b.aad
    }
}
