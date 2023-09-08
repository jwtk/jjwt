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
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class DefaultKeyOperationBuilderTest {

    private DefaultKeyOperationBuilder builder

    @Before
    void setUp() {
        this.builder = new DefaultKeyOperationBuilder()
    }

    @Test
    void testId() {
        def id = 'foo'
        def op = builder.id(id).build() as DefaultKeyOperation
        assertEquals id, op.id
        assertEquals DefaultKeyOperation.CUSTOM_DESCRIPTION, op.description
        assertFalse op.isRelated(Jwks.OP.SIGN)
    }

    @Test
    void testDescription() {
        def id = 'foo'
        def description = 'test'
        def op = builder.id(id).description(description).build()
        assertEquals id, op.id
        assertEquals 'test', op.description
    }

    @Test
    void testRelated() {
        def id = 'foo'
        def related = 'related'
        def opA = builder.id(id).related(related).build()
        def opB = builder.id(related).related(id).build()
        assertEquals id, opA.id
        assertEquals related, opB.id
        assertTrue opA.isRelated(opB)
        assertTrue opB.isRelated(opA)
        assertFalse opA.isRelated(Jwks.OP.SIGN)
        assertFalse opA.isRelated(Jwks.OP.SIGN)
    }

    @Test
    void testRelatedNull() {
        def op = builder.id('foo').related(null).build()
        assertTrue op.related.isEmpty()
    }

    @Test
    void testRelatedEmpty() {
        def op = builder.id('foo').related('  ').build()
        assertTrue op.related.isEmpty()
    }
}
