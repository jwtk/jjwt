/*
 * Copyright (C) 2018 jsonwebtoken.io
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

import java.security.SecureRandom

import static org.junit.Assert.assertTrue

/**
 * @since JJWT_RELEASE_VERSION
 */
class RandomsTest {

    @Test
    void testPrivateCtor() { //for code coverage only
        new Randoms()
    }

    @Test
    void testSecureRandom() {
        def random = Randoms.secureRandom()
        assertTrue random instanceof SecureRandom
    }
}
