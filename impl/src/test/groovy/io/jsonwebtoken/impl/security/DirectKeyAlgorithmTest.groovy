package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.lang.Arrays
import io.jsonwebtoken.security.DecryptionKeyRequest
import io.jsonwebtoken.security.EncryptionAlgorithms
import org.junit.Test

import javax.crypto.spec.SecretKeySpec
import java.security.Key

import static org.easymock.EasyMock.*
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertSame

class DirectKeyAlgorithmTest {

    @Test
    void testId() {
        assertEquals "dir", new DirectKeyAlgorithm().getId()
    }

    @Test
    void testGetEncryptionKey() {
        def alg = new DirectKeyAlgorithm()
        def key = new SecretKeySpec(new byte[1], "AES")
        def request = new DefaultKeyRequest(key, null, null, new DefaultJweHeader(), EncryptionAlgorithms.A128GCM)
        def result = alg.getEncryptionKey(request)
        assertSame key, result.getKey()
        assertEquals 0, Arrays.length(result.getPayload()) //must not have an encrypted key
    }

    @Test(expected = IllegalArgumentException)
    void testGetEncryptionKeyWithNullRequest() {
        new DirectKeyAlgorithm().getEncryptionKey(null)
    }

    @Test(expected = IllegalArgumentException)
    void testGetEncryptionKeyWithNullRequestKey() {
        def key = new SecretKeySpec(new byte[1], "AES")
        def request = new DefaultKeyRequest(key, null, null, new DefaultJweHeader(), EncryptionAlgorithms.A128GCM) {
            @Override
            Key getPayload() {
                return null
            }
        }
        new DirectKeyAlgorithm().getEncryptionKey(request)
    }

    @Test
    void testGetDecryptionKey() {
        def alg = new DirectKeyAlgorithm()
        DecryptionKeyRequest req = createMock(DecryptionKeyRequest)
        def key = EncryptionAlgorithms.A128GCM.keyBuilder().build()
        expect(req.getKey()).andReturn(key)
        replay(req)
        def result = alg.getDecryptionKey(req)
        verify(req)
        assertSame key, result
    }

    @Test(expected = IllegalArgumentException)
    void testGetDecryptionKeyWithNullRequest() {
        new DirectKeyAlgorithm().getDecryptionKey(null)
    }

    @Test(expected = IllegalArgumentException)
    void testGetDecryptionKeyWithNullRequestKey() {
        DecryptionKeyRequest req = createMock(DecryptionKeyRequest)
        expect(req.getKey()).andReturn(null)
        replay(req)
        new DirectKeyAlgorithm().getDecryptionKey(req)
    }
}
