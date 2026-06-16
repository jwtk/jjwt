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

import io.jsonwebtoken.impl.security.DefaultKeyOperationBuilder
import io.jsonwebtoken.impl.security.DefaultKeyOperationPolicyBuilder
import io.jsonwebtoken.impl.security.StandardKeyOperations
import org.junit.Test

import static org.junit.Assert.*

class JwkOpTest {

    @Test
    void testRegistry() {
        assertTrue Jwk.op.registry() instanceof StandardKeyOperations
    }

    @SuppressWarnings('GrDeprecatedAPIUsage')
    @Test
    void testBuilder() {
        assertTrue Jwks.OP.builder() instanceof DefaultKeyOperationBuilder
    }

    @SuppressWarnings('GrDeprecatedAPIUsage')
    @Test
    void testPolicy() {
        assertTrue Jwks.OP.policy() instanceof DefaultKeyOperationPolicyBuilder
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
        assertEquals op, Jwk.op.registry().get(id)
        assertSame op, Jwk.op.registry().get(id)
    }

    @Test
    void testInstances() {
        testInstance(Jwk.op.SIGN, 'sign', 'Compute digital signature or MAC', Jwk.op.VERIFY)
        testInstance(Jwk.op.VERIFY, 'verify', 'Verify digital signature or MAC', Jwk.op.SIGN)
        testInstance(Jwk.op.ENCRYPT, 'encrypt', 'Encrypt content', Jwk.op.DECRYPT)
        testInstance(Jwk.op.DECRYPT, 'decrypt', 'Decrypt content and validate decryption, if applicable', Jwk.op.ENCRYPT)
        testInstance(Jwk.op.WRAP_KEY, 'wrapKey', 'Encrypt key', Jwk.op.UNWRAP_KEY)
        testInstance(Jwk.op.UNWRAP_KEY, 'unwrapKey', 'Decrypt key and validate decryption, if applicable', Jwk.op.WRAP_KEY)

        testInstance(Jwk.op.DERIVE_KEY, 'deriveKey', 'Derive key', null)
        assertFalse Jwk.op.DERIVE_KEY.isRelated(Jwk.op.DERIVE_BITS)

        testInstance(Jwk.op.DERIVE_BITS, 'deriveBits', 'Derive bits not to be used as a key', null)
        assertFalse Jwk.op.DERIVE_BITS.isRelated(Jwk.op.DERIVE_KEY)
    }
}
