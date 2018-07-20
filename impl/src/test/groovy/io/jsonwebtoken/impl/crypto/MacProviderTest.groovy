/*
 * Copyright (C) 2015 jsonwebtoken.io
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
package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.SignatureAlgorithm
import org.junit.Test
import static org.junit.Assert.*

class MacProviderTest {

    @Test
    void testDefault() {
        byte[] bytes = MacProvider.generateKey().encoded
        assertEquals 64, bytes.length
    }

    @Test
    void testHS256() {
        byte[] bytes = MacProvider.generateKey(SignatureAlgorithm.HS256).encoded
        assertEquals 32, bytes.length
    }

    @Test
    void testHS384() {
        byte[] bytes = MacProvider.generateKey(SignatureAlgorithm.HS384).encoded
        assertEquals 48, bytes.length
    }

    @Test
    void testHS512() {
        byte[] bytes = MacProvider.generateKey(SignatureAlgorithm.HS512).encoded
        assertEquals 64, bytes.length
    }
}
