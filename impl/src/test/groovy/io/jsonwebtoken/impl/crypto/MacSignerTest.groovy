/*
 * Copyright (C) 2014 jsonwebtoken.io
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
package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import javax.crypto.Mac
import java.security.InvalidKeyException
import java.security.Key
import java.security.NoSuchAlgorithmException

import static org.junit.Assert.*

class MacSignerTest {

    private static final Random rng = new Random(); //doesn't need to be secure - we're just testing

    @Test
    void testCtorArgNotASecretKey() {

        def key = new Key() {
            @Override
            String getAlgorithm() {
                return null
            }

            @Override
            String getFormat() {
                return null
            }

            @Override
            byte[] getEncoded() {
                return new byte[0]
            }
        }

        try {
            new MacSigner(SignatureAlgorithm.HS256, key)
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testNoSuchAlgorithmException() {
        byte[] key = new byte[32];
        byte[] data = new byte[32];
        rng.nextBytes(key);
        rng.nextBytes(data);

        def s = new MacSigner(SignatureAlgorithm.HS256, key) {
            @Override
            protected Mac doGetMacInstance() throws NoSuchAlgorithmException, InvalidKeyException {
                throw new NoSuchAlgorithmException("foo");
            }
        }
        try {
            s.sign(data);
            fail();
        } catch (SignatureException e) {
            assertTrue e.cause instanceof NoSuchAlgorithmException
            assertEquals e.cause.message, 'foo'
        }
    }

    @Test
    void testInvalidKeyException() {
        byte[] key = new byte[32];
        byte[] data = new byte[32];
        rng.nextBytes(key);
        rng.nextBytes(data);

        def s = new MacSigner(SignatureAlgorithm.HS256, key) {
            @Override
            protected Mac doGetMacInstance() throws NoSuchAlgorithmException, InvalidKeyException {
                throw new InvalidKeyException("foo");
            }
        }
        try {
            s.sign(data);
            fail();
        } catch (SignatureException e) {
            assertTrue e.cause instanceof InvalidKeyException
            assertEquals e.cause.message, 'foo'
        }
    }
}
