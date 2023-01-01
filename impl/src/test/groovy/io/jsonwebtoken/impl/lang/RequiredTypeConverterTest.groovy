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
package io.jsonwebtoken.impl.lang

import org.junit.Test

import static org.junit.Assert.*

/**
 * @since JJWT_RELEASE_VERSION
 */
class RequiredTypeConverterTest {

    @Test
    void testApplyTo() {
        def converter = new RequiredTypeConverter(Integer.class)
        def val = 42
        assertSame val, converter.applyTo(val)
    }

    @Test
    void testApplyFromNull() {
        def converter = new RequiredTypeConverter(Integer.class)
        assertNull converter.applyFrom(null)
    }

    @Test
    void testApplyFromInvalidType() {
        def converter = new RequiredTypeConverter(Integer.class)
        try {
            converter.applyFrom('hello' as String)
        } catch (IllegalArgumentException expected) {
            String msg = 'Unsupported value type. Expected: java.lang.Integer, found: java.lang.String'
            assertEquals msg, expected.getMessage()
        }
    }
}
