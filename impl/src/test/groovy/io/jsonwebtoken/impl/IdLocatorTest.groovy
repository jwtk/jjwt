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
package io.jsonwebtoken.impl

import io.jsonwebtoken.Identifiable
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.impl.lang.IdRegistry
import io.jsonwebtoken.impl.lang.Parameter
import io.jsonwebtoken.impl.lang.Parameters
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class IdLocatorTest {

    private static final String exMsg = 'foo is required'
    private static final Parameter<String> TEST_PARAM = Parameters.string('foo', 'Foo')

    private static IdRegistry registry
    private static IdLocator locator

    @Before
    void setUp() {
        def a = new StringIdentifiable(value: 'A')
        def b = new StringIdentifiable(value: 'B')
        registry = new IdRegistry('Foo', [a, b], false)
        locator = new IdLocator(TEST_PARAM, registry, Collections.emptyList(), exMsg)
    }

    @Test
    void unrequiredHeaderValueTest() {
        locator = new IdLocator(TEST_PARAM, registry, Collections.emptyList(), null)
        def header = Jwts.header().add('a', 'b').build()
        assertNull locator.apply(header)
    }

    @Test
    void missingRequiredHeaderValueTest() {
        def header = Jwts.header().build()
        try {
            locator.apply(header)
            fail()
        } catch (MalformedJwtException expected) {
            assertEquals exMsg, expected.getMessage()
        }
    }

    @Test
    void unlocatableJwtHeaderInstanceTest() {
        def header = Jwts.header().add('foo', 'foo').build()
        try {
            locator.apply(header)
        } catch (UnsupportedJwtException expected) {
            String msg = "Unrecognized JWT ${TEST_PARAM} header value: foo"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void unlocatableJwsHeaderInstanceTest() {
        def header = Jwts.header().add('alg', 'HS256').add('foo', 'foo').build()
        try {
            locator.apply(header)
        } catch (UnsupportedJwtException expected) {
            String msg = "Unrecognized JWS ${TEST_PARAM} header value: foo"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void unlocatableJweHeaderInstanceTest() {
        def header = Jwts.header().add('enc', 'A256GCM').add('foo', 'foo').build()
        try {
            locator.apply(header)
        } catch (UnsupportedJwtException expected) {
            String msg = "Unrecognized JWE ${TEST_PARAM} header value: foo"
            assertEquals msg, expected.getMessage()
        }
    }

    static class StringIdentifiable implements Identifiable {
        String value;

        @Override
        String getId() {
            return value;
        }
    }
}
