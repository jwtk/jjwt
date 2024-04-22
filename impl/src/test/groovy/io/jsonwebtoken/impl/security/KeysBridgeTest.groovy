/*
 * Copyright © 2023 jsonwebtoken.io
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

import org.junit.Test

import javax.crypto.SecretKey
import java.security.Key
import java.security.PrivateKey

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertFalse
import static org.junit.Assert.assertTrue

class KeysBridgeTest {

    @Test
    void testToStringKeyNull() {
        assertEquals 'null', KeysBridge.toString(null)
    }

    @Test
    void testToStringPublicKey() {
        // should just be key.toString(). Because it's a PublicKey, no danger of reporting key data
        def key = TestKeys.ES256.pair.public
        String s = KeysBridge.toString(key)
        assertEquals key.toString(), s
    }

    static void testFormattedOutput(Key key) {
        String s = KeysBridge.toString(key)
        String expected = "class: ${key.getClass().getName()}, algorithm: ${key.getAlgorithm()}, format: ${key.getFormat()}" as String
        assertEquals expected, s
    }

    @Test
    void testToStringPrivateKey() {
        testFormattedOutput(TestKeys.ES256.pair.private)
    }

    @Test
    void testToStringSecretKey() {
        testFormattedOutput(TestKeys.HS256)
    }

    @Test
    void testToStringPassword() {
        testFormattedOutput(new PasswordSpec("foo".toCharArray()))
    }

    @Test
    void testIsGenericSecret() {
        def secretKeyWithAlg = { alg ->
            new SecretKey() {
                @Override
                String getAlgorithm() {
                    return alg
                }

                @Override
                String getFormat() {
                    return 'RAW'
                }

                @Override
                byte[] getEncoded() {
                    return new byte[0]
                }
            }
        }

        PrivateKey genericPrivateKey = new PrivateKey() {
            @Override
            String getAlgorithm() {
                return "Generic"
            }

            @Override
            String getFormat() {
                return "RAW"
            }

            @Override
            byte[] getEncoded() {
                return new byte[0]
            }
        }

        assertTrue KeysBridge.isGenericSecret(secretKeyWithAlg("GenericSecret"))
        assertTrue KeysBridge.isGenericSecret(secretKeyWithAlg("Generic Secret"))
        assertFalse KeysBridge.isGenericSecret(secretKeyWithAlg(" Generic"))
        assertFalse KeysBridge.isGenericSecret(TestKeys.HS256)
        assertFalse KeysBridge.isGenericSecret(TestKeys.A256GCM)
        assertFalse KeysBridge.isGenericSecret(genericPrivateKey)
    }
}
