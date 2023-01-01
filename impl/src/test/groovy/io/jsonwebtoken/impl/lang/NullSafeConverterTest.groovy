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

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNull

class NullSafeConverterTest {

    @Test
    void testNullArguments() {
        def converter = new NullSafeConverter(new UriStringConverter())
        assertNull converter.applyTo(null)
        assertNull converter.applyFrom(null)
    }

    @Test
    void testNonNullArguments() {
        def converter = new NullSafeConverter(new UriStringConverter())
        String url = 'https://github.com/jwtk/jjwt'
        URI uri = new URI(url)
        assertEquals url, converter.applyTo(uri)
        assertEquals uri, converter.applyFrom(url)
    }
}
