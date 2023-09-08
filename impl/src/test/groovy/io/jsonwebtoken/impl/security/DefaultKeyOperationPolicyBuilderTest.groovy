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

import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.KeyOperation
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class DefaultKeyOperationPolicyBuilderTest {

    DefaultKeyOperationPolicyBuilder builder

    @Before
    void setUp() {
        builder = new DefaultKeyOperationPolicyBuilder()
    }

    @Test
    void testDefault() {
        def policy = builder.build()
        assertTrue policy.operations.containsAll(Jwks.OP.get().values())
        // unrelated operations not allowed:
        def op = Jwks.OP.builder().id('foo').build()
        try {
            policy.validate([op, Jwks.OP.SIGN])
            fail("Unrelated operations are not allowed by default.")
        } catch (IllegalArgumentException expected) {
            String msg = 'Unrelated key operations are not allowed. KeyOperation ' +
                    '[\'sign\' (Compute digital signature or MAC)] is unrelated to [\'foo\' (Custom key operation)].'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testAdd() {
        def op = Jwks.OP.builder().id('foo').build()
        def policy = builder.add(op).build()
        assertTrue policy.operations.contains(op)
    }

    @Test
    void testAddNull() {
        def orig = builder.build()
        def policy = builder.add((KeyOperation) null).build()
        assertEquals orig, policy
    }

    @Test
    void testAddCollection() {
        def foo = Jwks.OP.builder().id('foo').build()
        def bar = Jwks.OP.builder().id('bar').build()
        def policy = builder.add([foo, bar]).build()
        assertTrue policy.operations.contains(foo)
        assertTrue policy.operations.contains(bar)
    }

    @Test
    void testAddNullCollection() {
        def orig = builder.build()
        def policy = builder.add((Collection<KeyOperation>) null).build()
        assertEquals orig, policy
    }

    @Test
    void testAllowUnrelatedTrue() { // testDefault has it false as expected
        def foo = Jwks.OP.builder().id('foo').build()
        def policy = builder.allowUnrelated(true).build()
        policy.validate([foo, Jwks.OP.SIGN]) // no exception thrown since unrelated == true
    }

    @Test
    void testHashCode() {
        def a = builder.add(Jwks.OP.builder().id('foo').build()).build()
        def b = builder.build()
        assertFalse a.is(b) // identity equals is different
        def ahc = a.hashCode()
        def bhc = b.hashCode()
        assertEquals ahc, bhc // still same hashcode
    }

    @Test
    void testEquals() {
        def a = builder.add(Jwks.OP.builder().id('foo').build()).build()
        def b = builder.build()
        assertFalse a.is(b) // identity equals is different
        assertEquals a, b // but still equals
    }

    @Test
    void testEqualsIdentity() {
        def policy = builder.build()
        assertEquals policy, policy
    }

    @SuppressWarnings('ChangeToOperator')
    @Test
    void testEqualsUnexpectedType() {
        assertFalse builder.build().equals(new Object())
    }
}
