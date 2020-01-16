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
import io.jsonwebtoken.security.Keys
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class DefaultSignerFactoryTest {

    @Test
    void testCreateSignerWithNoneAlgorithm() {

        def factory = new DefaultSignerFactory();

        try {
            factory.createSigner(SignatureAlgorithm.none, Keys.secretKeyFor(SignatureAlgorithm.HS256))
            fail();
        } catch (IllegalArgumentException iae) {
            assertEquals iae.message, "The 'none' algorithm cannot be used for signing."
        }
    }

}
