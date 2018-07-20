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

class DefaultSignatureValidatorFactoryTest {

    @Test
    void testNoneAlgorithm() {
        try {
            new DefaultSignatureValidatorFactory().createSignatureValidator(SignatureAlgorithm.NONE, MacProvider.generateKey())
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals iae.message, "The 'NONE' algorithm cannot be used for signing."
        }
    }
}
