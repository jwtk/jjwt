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
package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.SignatureAlgorithm
import org.testng.annotations.Test

import javax.crypto.spec.SecretKeySpec

import static org.testng.Assert.*

class DefaultSignerFactoryTest {

    private static final Random rng = new Random(); //doesn't need to be secure - we're just testing

    @Test
    void testCreateSignerWithNoneAlgorithm() {

        byte[] keyBytes = new byte[32];
        rng.nextBytes(keyBytes);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "foo");

        def factory = new DefaultSignerFactory();

        try {
            factory.createSigner(SignatureAlgorithm.NONE, key);
            fail();
        } catch (IllegalArgumentException iae) {
            assertEquals iae.message, "The 'NONE' algorithm cannot be used for signing."
        }
    }

}
