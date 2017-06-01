package io.jsonwebtoken.impl.crypto

import org.junit.Test

import static org.junit.Assert.*

class DefaultEncryptionResultTest {

    private byte[] generateData() {
        byte[] data = new byte[32];
        new Random().nextBytes(data) //does not need to be secure for this test
        return data;
    }

    @Test
    void testCompactWithoutIv() {
        def ciphertext = generateData()
        def result = new DefaultEncryptionResult(null, ciphertext)
        assertSame ciphertext, result.compact()
    }

    @Test
    void testCompactWithIv() {
        def ciphertext = generateData()
        def iv = generateData()

        byte[] result = new DefaultEncryptionResult(iv, ciphertext).compact()

        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);

        assertTrue Arrays.equals(combined, result)
    }
}
