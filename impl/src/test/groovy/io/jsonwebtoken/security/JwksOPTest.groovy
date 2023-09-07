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
package io.jsonwebtoken.security

import io.jsonwebtoken.impl.security.StandardKeyOperations
import org.junit.Test

import static org.junit.Assert.*

class JwksOPTest {

    @Test
    void testRegistry() {
        assertTrue Jwks.OP.get() instanceof StandardKeyOperations
    }

    static void testInstance(KeyOperation op, String id, String description, KeyOperation related) {
        assertEquals id, op.getId()
        assertEquals description, op.getDescription()
        if (related) {
            assertFalse(op.isUnrelated(related))
        }
        assertEquals id.hashCode(), op.hashCode()
        assertEquals "'$id' ($description)" as String, op.toString()
        assertTrue op.equals(op)
        assertTrue op.is(op)
        assertTrue op == op
        assertEquals op, Jwks.OP.get().get(id)
        assertSame op, Jwks.OP.get().get(id)
    }

    @Test
    void testInstances() {
        testInstance(Jwks.OP.SIGN, 'sign', 'Compute digital signature or MAC', Jwks.OP.VERIFY)
        testInstance(Jwks.OP.VERIFY, 'verify', 'Verify digital signature or MAC', Jwks.OP.SIGN)
        testInstance(Jwks.OP.ENCRYPT, 'encrypt', 'Encrypt content', Jwks.OP.DECRYPT)
        testInstance(Jwks.OP.DECRYPT, 'decrypt', 'Decrypt content and validate decryption, if applicable', Jwks.OP.ENCRYPT)
        testInstance(Jwks.OP.WRAP, 'wrapKey', 'Encrypt key', Jwks.OP.UNWRAP)
        testInstance(Jwks.OP.UNWRAP, 'unwrapKey', 'Decrypt key and validate decryption, if applicable', Jwks.OP.WRAP)

        testInstance(Jwks.OP.DERIVE_KEY, 'deriveKey', 'Derive key', null)
        assertTrue Jwks.OP.DERIVE_KEY.isUnrelated(Jwks.OP.DERIVE_BITS)

        testInstance(Jwks.OP.DERIVE_BITS, 'deriveBits', 'Derive bits not to be used as a key', null)
        assertTrue Jwks.OP.DERIVE_BITS.isUnrelated(Jwks.OP.DERIVE_KEY)
    }
}
