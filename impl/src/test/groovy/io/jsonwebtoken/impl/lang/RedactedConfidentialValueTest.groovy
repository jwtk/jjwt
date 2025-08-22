/*
 * Copyright (C) 2022 jsonwebtoken.io
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

class RedactedConfidentialValueTest {

    @Test
    void testEqualsWrappedSameValue() {
        def value = 42
        assertTrue new RedactedConfidentialValue<>(value).equals(value)
    }

    @Test
    void testEqualsWrappedDifferentValue() {
        assertFalse new RedactedConfidentialValue<>(42).equals(30)
    }

    @Test
    void testEquals() {
        assertTrue new RedactedConfidentialValue<>(42).equals(new RedactedConfidentialValue(42))
    }

    @Test
    void testEqualsSameTypeDifferentValue() {
        assertFalse new RedactedConfidentialValue<>(42).equals(new RedactedConfidentialValue(30))
    }

    @Test
    void testEqualsIdentity() {
        def supplier = new RedactedConfidentialValue('hello')
        assertEquals supplier, supplier
    }

    @Test
    void testHashCode() {
        int hashCode = 42.hashCode()
        assertEquals hashCode, new RedactedConfidentialValue(42).hashCode()
    }

}
