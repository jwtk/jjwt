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
package io.jsonwebtoken


import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.impl.DefaultJwsHeader
import org.junit.Test

import static org.junit.Assert.assertNull
import static org.junit.Assert.assertSame

class LocatorAdapterTest {

    @Test
    void testJwtHeader() {
        Header input = Jwts.header().build()
        def locator = new LocatorAdapter() {
            @Override
            protected Object doLocate(Header header) {
                return header
            }
        }
        assertSame input, locator.locate(input as Header /* force Groovy to avoid signature erasure */)
    }

    @Test
    void testJwtHeaderWithoutOverride() {
        Header input = Jwts.header().build()
        Locator locator = new LocatorAdapter() {}
        assertNull locator.locate(input as Header /* force Groovy to avoid signature erasure */)
    }

    @Test
    void testJwsHeader() {
        Header input = new DefaultJwsHeader([:])
        Locator locator = new LocatorAdapter() {
            @Override
            protected Object locate(JwsHeader header) {
                return header
            }
        }
        assertSame input, locator.locate(input as Header /* force Groovy to avoid signature erasure */)
    }

    @Test
    void testJwsHeaderWithoutOverride() {
        Header input = new DefaultJwsHeader([:])
        Locator locator = new LocatorAdapter() {}
        assertNull locator.locate(input as Header)
    }

    @Test
    void testJweHeader() {
        JweHeader input = new DefaultJweHeader([:])
        def locator = new LocatorAdapter() {
            @Override
            protected Object locate(JweHeader header) {
                return header
            }
        }
        assertSame input, locator.locate(input as Header)
    }

    @Test
    void testJweHeaderWithoutOverride() {
        JweHeader input = new DefaultJweHeader([:])
        def locator = new LocatorAdapter() {}
        assertNull locator.locate(input as Header)
    }
}
