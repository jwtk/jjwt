/*
 * Copyright (C) 2020 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.lang.Arrays
import io.jsonwebtoken.security.DecryptionKeyRequest
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
        def request = new DefaultKeyRequest(key, null, null, new DefaultJweHeader([:]), Jwts.ENC.A128GCM)
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
        def request = new DefaultKeyRequest(key, null, null, new DefaultJweHeader([:]), Jwts.ENC.A128GCM) {
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
        def key = Jwts.ENC.A128GCM.key().build()
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
