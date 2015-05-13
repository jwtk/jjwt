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

import org.junit.Test
import static org.junit.Assert.*

class JwtHandlerAdapterTest {

    @Test
    void testOnPlaintextJwt() {
        def handler = new JwtHandlerAdapter();
        try {
            handler.onPlaintextJwt(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Unsigned plaintext JWTs are not supported.'
        }
    }

    @Test
    void testOnClaimsJwt() {
        def handler = new JwtHandlerAdapter();
        try {
            handler.onClaimsJwt(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Unsigned Claims JWTs are not supported.'
        }
    }

    @Test
    void testOnPlaintextJws() {
        def handler = new JwtHandlerAdapter();
        try {
            handler.onPlaintextJws(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Signed plaintext JWSs are not supported.'
        }
    }

    @Test
    void testOnClaimsJws() {
        def handler = new JwtHandlerAdapter();
        try {
            handler.onClaimsJws(null)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Signed Claims JWSs are not supported.'
        }
    }
}
