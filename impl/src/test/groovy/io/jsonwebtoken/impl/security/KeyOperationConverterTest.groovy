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
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertSame

class KeyOperationConverterTest {

    @Test
    void testApplyFromStandardId() {
        Jwks.OP.get().values().each {
            def id = it.id
            def op = KeyOperationConverter.DEFAULT.applyFrom(id)
            assertSame it, op
        }
    }

    @Test
    void testApplyFromCustomId() {
        def id = 'custom'
        def op = KeyOperationConverter.DEFAULT.applyFrom(id)
        assertEquals id, op.id
        assertEquals DefaultKeyOperation.CUSTOM_DESCRIPTION, op.description
    }
}
