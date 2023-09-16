/*
 * Copyright (C) 2021 jsonwebtoken.io
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
import org.junit.Test

import java.security.Key
import java.security.KeyPair
import java.security.PublicKey
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class KeyPairsTest {

    @Test
    void testPrivateCtor() { // for code coverage only
        new KeyPairs()
    }

    @Test
    void testGetKeyNullPair() {
        try {
            KeyPairs.getKey(null, ECPublicKey.class)
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals 'KeyPair cannot be null.', iae.getMessage()
        }
    }

    @Test
    void testUnrecognizedFamily() {
        PublicKey pub = new TestECPublicKey()
        KeyPair pair = new KeyPair(pub, new TestECPrivateKey())
        Class clazz = DSAPublicKey // unrecognized --> no 'family' prefix in message
        try {
            KeyPairs.getKey(pair, clazz)
            fail()
        } catch (IllegalArgumentException iae) {
            String msg = "KeyPair public key must be an instance of ${clazz.name}. Type found: ${pub.class.name}"
            assertEquals msg, iae.getMessage()
        }
    }

    @Test
    void testGetKeyECMismatch() {
        KeyPair pair = Jwts.SIG.RS256.keyPair().build()
        Class clazz = ECPublicKey
        try {
            KeyPairs.getKey(pair, clazz)
        } catch (IllegalArgumentException iae) {
            String msg = "EC KeyPair public key must be an instance of ${clazz.name}. Type found: ${pair.public.class.name}"
            assertEquals msg, iae.getMessage()
        }
    }

    @Test
    void testGetKeyRSAMismatch() {
        KeyPair pair = new KeyPair(new TestECPublicKey(), new TestECPrivateKey())
        Class clazz = RSAPublicKey
        try {
            KeyPairs.getKey(pair, clazz)
        } catch (IllegalArgumentException iae) {
            String msg = "RSA KeyPair public key must be an instance of ${clazz.name}. Type found: ${pair.public.class.name}"
            assertEquals msg, iae.getMessage()
        }
    }

    @Test
    void testAssertPublicKeyTypeMismatch() {
        Key key = new TestECPublicKey()
        Class clazz = RSAPublicKey
        String prefix = 'Foo '
        try {
            KeyPairs.assertKey(key, clazz, prefix)
            fail()
        } catch (IllegalArgumentException iae) {
            String msg = "${prefix}public key must be an instance of ${clazz.name}. Type found: ${key.class.name}"
            assertEquals msg, iae.getMessage()
        }
    }

    @Test
    void testAssertPrivateKeyTypeMismatch() {
        Key key = new TestECPrivateKey()
        Class clazz = RSAPrivateKey
        String prefix = 'Foo '
        try {
            KeyPairs.assertKey(key, clazz, prefix)
            fail()
        } catch (IllegalArgumentException iae) {
            String msg = "${prefix}private key must be an instance of ${clazz.name}. Type found: ${key.class.name}"
            assertEquals msg, iae.getMessage()
        }
    }

    private void printMap(Map<?, ?> m, int indentCount) {
        for (def entry : m.entrySet()) {
            indentCount.times { print("\t") }
            print "${entry.key}: "
            if (entry.value instanceof Map) {
                println()
                printMap(entry.value as Map, indentCount + 1)
            } else {
                println "${entry.value}"
            }
        }
    }
}
