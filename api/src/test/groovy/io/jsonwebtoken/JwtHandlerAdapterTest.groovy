/*
 * Copyright (C) 2014 jsonwebtoken.io
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
package io.jsonwebtoken

import org.junit.Before
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class JwtHandlerAdapterTest {

    private JwtHandlerAdapter handler

    @Before
    void setUp() {
        handler = new JwtHandlerAdapter(){}
    }

    @Test
    void testOnPlaintextJwt() {
        try {
            handler.onPayloadJwt(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Unsigned plaintext JWTs are not supported.'
        }
    }

    @Test
    void testOnClaimsJwt() {
        try {
            handler.onClaimsJwt(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Unsigned Claims JWTs are not supported.'
        }
    }

    @Test
    void testOnPlaintextJws() {
        try {
            handler.onPlaintextJws(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Signed plaintext JWTs are not supported.'
        }
    }

    @Test
    void testOnClaimsJws() {
        try {
            handler.onClaimsJws(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Signed Claims JWTs are not supported.'
        }
    }

    @Test
    void testOnPlaintextJwe() {
        try {
            handler.onPlaintextJwe(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Encrypted plaintext JWTs are not supported.'
        }
    }

    @Test
    void testOnClaimsJwe() {
        try {
            handler.onClaimsJwe(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Encrypted Claims JWTs are not supported.'
        }
    }
}
