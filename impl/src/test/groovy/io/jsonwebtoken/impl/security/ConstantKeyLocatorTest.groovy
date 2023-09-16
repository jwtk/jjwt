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

import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.impl.DefaultHeader
import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.impl.DefaultJwsHeader
import org.junit.Test

import javax.crypto.spec.SecretKeySpec

import static org.junit.Assert.*

class ConstantKeyLocatorTest {

    @Test
    void testSignatureVerificationKey() {
        def key = new SecretKeySpec(new byte[1], 'AES') //dummy key for testing
        assertSame key, new ConstantKeyLocator(key, null).locate(new DefaultJwsHeader([:]))
    }

    @Test
    void testSignatureVerificationKeyMissing() {
        def locator = new ConstantKeyLocator(null, null)
        try {
            locator.locate(new DefaultJwsHeader([:]))
        } catch (UnsupportedJwtException uje) {
            String msg = 'Signed JWTs are not supported: the JwtParser has not been configured with a signature ' +
                    'verification key or a KeyResolver. Consider configuring the JwtParserBuilder with one of these ' +
                    'to ensure it can use the necessary key to verify JWS signatures.'
            assertEquals msg, uje.getMessage()
        }
    }

    @Test
    void testDecryptionKey() {
        def key = new SecretKeySpec(new byte[1], 'AES') //dummy key for testing
        assertSame key, new ConstantKeyLocator(null, key).locate(new DefaultJweHeader([:]))
    }

    @Test
    void testDecryptionKeyMissing() {
        def locator = new ConstantKeyLocator(null, null)
        try {
            locator.locate(new DefaultJweHeader([:]))
        } catch (UnsupportedJwtException uje) {
            String msg = 'Encrypted JWTs are not supported: the JwtParser has not been configured with a decryption ' +
                    'key or a KeyResolver. Consider configuring the JwtParserBuilder with one of these ' +
                    'to ensure it can use the necessary key to decrypt JWEs.'
            assertEquals msg, uje.getMessage()
        }
    }

    @Test
    void testApply() {
        def locator = new ConstantKeyLocator(null, null)
        assertNull locator.apply(new DefaultHeader([:]))
    }
}
