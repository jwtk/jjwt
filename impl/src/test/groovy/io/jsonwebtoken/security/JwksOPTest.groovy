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
            assertTrue op.isRelated(related)
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
        testInstance(Jwks.OP.WRAP_KEY, 'wrapKey', 'Encrypt key', Jwks.OP.UNWRAP_KEY)
        testInstance(Jwks.OP.UNWRAP_KEY, 'unwrapKey', 'Decrypt key and validate decryption, if applicable', Jwks.OP.WRAP_KEY)

        testInstance(Jwks.OP.DERIVE_KEY, 'deriveKey', 'Derive key', null)
        assertFalse Jwks.OP.DERIVE_KEY.isRelated(Jwks.OP.DERIVE_BITS)

        testInstance(Jwks.OP.DERIVE_BITS, 'deriveBits', 'Derive bits not to be used as a key', null)
        assertFalse Jwks.OP.DERIVE_BITS.isRelated(Jwks.OP.DERIVE_KEY)
    }
}
