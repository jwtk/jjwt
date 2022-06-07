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
    void testOnContentJwt() {
        try {
            handler.onContentJwt(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Unprotected content JWTs are not supported.', e.getMessage()
        }
    }

    @Test
    void testOnClaimsJwt() {
        try {
            handler.onClaimsJwt(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Unprotected Claims JWTs are not supported.', e.getMessage()
        }
    }

    @Test
    void testOnContentJws() {
        try {
            handler.onContentJws(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Signed content JWTs are not supported.', e.getMessage()
        }
    }

    @Test
    void testOnClaimsJws() {
        try {
            handler.onClaimsJws(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Signed Claims JWTs are not supported.', e.getMessage()
        }
    }

    @Test
    void testOnContentJwe() {
        try {
            handler.onContentJwe(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Encrypted content JWTs are not supported.', e.getMessage()
        }
    }

    @Test
    void testOnClaimsJwe() {
        try {
            handler.onClaimsJwe(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Encrypted Claims JWTs are not supported.', e.getMessage()
        }
    }
}
