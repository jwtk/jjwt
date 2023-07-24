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

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.impl.lang.Field
import io.jsonwebtoken.impl.lang.Fields
import io.jsonwebtoken.impl.lang.Functions
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class IdLocatorTest {

    private static final Field<String> TEST_FIELD = Fields.string('foo', 'Foo')

    @Test
    void missingRequiredHeaderValueTest() {
        def msg = 'foo is required'
        def loc = new IdLocator(TEST_FIELD, 'foo is required', Functions.forNull())
        def header = Jwts.header().build()
        try {
            loc.apply(header)
            fail()
        } catch (MalformedJwtException expected) {
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void unlocatableJwtHeaderInstanceTest() {
        def loc = new IdLocator(TEST_FIELD, 'foo is required', Functions.forNull())
        def header = Jwts.header().set('foo', 'foo').build()
        try {
            loc.apply(header)
        } catch (UnsupportedJwtException expected) {
            String msg = "Unrecognized JWT ${TEST_FIELD} header value: foo"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void unlocatableJwsHeaderInstanceTest() {
        def loc = new IdLocator(TEST_FIELD, 'foo is required', Functions.forNull())
        def header = Jwts.header().setAlgorithm('HS256').set('foo', 'foo').build()
        try {
            loc.apply(header)
        } catch (UnsupportedJwtException expected) {
            String msg = "Unrecognized JWS ${TEST_FIELD} header value: foo"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void unlocatableJweHeaderInstanceTest() {
        def loc = new IdLocator(TEST_FIELD, 'foo is required', Functions.forNull())
        def header = new DefaultJweHeader([foo: 'foo'])
        try {
            loc.apply(header)
        } catch (UnsupportedJwtException expected) {
            String msg = "Unrecognized JWE ${TEST_FIELD} header value: foo"
            assertEquals msg, expected.getMessage()
        }
    }
}
