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
package io.jsonwebtoken.io

import org.junit.Test

import static org.junit.Assert.assertTrue

class EncodersTest {

    @Test
    void testPrivateCtor() {
        new Encoders() //not allowed in java, including here only to pass test coverage assertions
    }

    @Test
    void testBase64() {
        assertTrue Encoders.BASE64 instanceof ExceptionPropagatingEncoder
        assertTrue Encoders.BASE64.encoder instanceof Base64Encoder
    }

    @Test
    void testBase64Url() {
        assertTrue Encoders.BASE64URL instanceof ExceptionPropagatingEncoder
        assertTrue Encoders.BASE64URL.encoder instanceof Base64UrlEncoder
    }
}
