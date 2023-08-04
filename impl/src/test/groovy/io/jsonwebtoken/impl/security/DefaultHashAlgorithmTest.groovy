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

import io.jsonwebtoken.security.HashAlgorithm
import io.jsonwebtoken.security.Jwks
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.assertTrue

class DefaultHashAlgorithmTest {

    static final def algs = [DefaultHashAlgorithm.SHA1, Jwks.HASH.SHA256]

    @Test
    void testDigestAndVerify() {
        byte[] data = "Hello World".getBytes(StandardCharsets.UTF_8)
        for (HashAlgorithm alg : algs) {
            byte[] hash = alg.digest(new DefaultRequest<byte[]>(data, null, null))
            assertTrue alg.verify(new DefaultVerifyDigestRequest(data, null, null, hash))
        }
    }
}
