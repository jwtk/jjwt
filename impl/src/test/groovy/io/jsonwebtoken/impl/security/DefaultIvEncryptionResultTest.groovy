package io.jsonwebtoken.impl.security

import org.junit.Test

import static org.junit.Assert.assertSame
import static org.junit.Assert.assertTrue

/**
 * @since JJWT_RELEASE_VERSION
 */
class DefaultIvEncryptionResultTest {

    private byte[] generateData() {
        byte[] data = new byte[32];
        new Random().nextBytes(data) //does not need to be secure for this test
        return data;
    }

    @Test(expected=IllegalArgumentException)
    void testCompactWithoutIv() {
        def ciphertext = generateData()
        new DefaultIvEncryptionResult(ciphertext, null)
    }

    @Test
    void testCompactWithIv() {
        def ciphertext = generateData()
        def iv = generateData()

        byte[] result = new DefaultIvEncryptionResult(ciphertext, iv).compact()

        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);

        assertTrue Arrays.equals(combined, result)
    }
}
