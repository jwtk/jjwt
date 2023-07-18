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
package io.jsonwebtoken.security

import io.jsonwebtoken.Jwts
import org.junit.Test

import static org.junit.Assert.assertNotNull

/**
 * The {@link StandardAlgorithmsTest} class contains the majority of test cases relevant for the
 * {@link StandardSecureDigestAlgorithms} implementation.  This test class exists for additional checks/assertions
 * for the convenience Ed2448 and Ed25519 aliases.
 */
class StandardSecureDigestAlgorithmsTest {

    @Test
    void testFindEd448() {
        assertNotNull Jwts.SIG.find('Ed448')
    }

    @Test
    void testFindEd448CaseInsensitive() {
        assertNotNull Jwts.SIG.find('ED448')
        assertNotNull Jwts.SIG.find('ed448')
    }

    @Test
    void testFindEd25519() {
        assertNotNull Jwts.SIG.find('Ed25519')
    }

    @Test
    void testFindEd25519CaseInsensitive() {
        assertNotNull Jwts.SIG.find('ED25519')
        assertNotNull Jwts.SIG.find('ed25519')
    }
}
