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
package io.jsonwebtoken.impl.security

import org.junit.Test

import static org.junit.Assert.assertEquals

class DefaultJwkContextTest {

    @Test
    void testGetName() {
        def header = new DefaultJwkContext()
        assertEquals 'JWK', header.getName()
    }

    @Test
    void testGetNameWhenSecretKey() {
        def header = new DefaultJwkContext(DefaultSecretJwk.FIELDS)
        header.put('kty', 'oct')
        assertEquals 'Secret JWK', header.getName()
    }

    @Test
    void testGStringPrintsRedactedValues() {
        // DO NOT REMOVE THIS METHOD: IT IS CRITICAL TO ENSURE GROOVY STRINGS DO NOT LEAK SECRET/PRIVATE KEY MATERIAL
        def header = new DefaultJwkContext(DefaultSecretJwk.FIELDS)
        header.put('kty', 'oct')
        header.put('k', 'test')
        String s = '[kty:oct, k:<redacted>]'
        assertEquals "$s", "$header"
    }

    @Test
    void testGStringToStringPrintsRedactedValues() {
        def header = new DefaultJwkContext(DefaultSecretJwk.FIELDS)
        header.put('kty', 'oct')
        header.put('k', 'test')
        String s = '{kty=oct, k=<redacted>}'
        assertEquals "$s", "${header.toString()}"
    }
}
