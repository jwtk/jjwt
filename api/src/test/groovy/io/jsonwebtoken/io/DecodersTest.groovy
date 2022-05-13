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

class DecodersTest {

    @Test
    void testPrivateCtor() {
        new Decoders() //not allowed in java, including here only to pass test coverage assertions
    }

    @Test
    void testBase64() {
        assertTrue Decoders.BASE64 instanceof ExceptionPropagatingDecoder
        assertTrue Decoders.BASE64.decoder instanceof Base64Decoder
    }

    @Test
    void testBase64Url() {
        assertTrue Decoders.BASE64URL instanceof ExceptionPropagatingDecoder
        assertTrue Decoders.BASE64URL.decoder instanceof Base64UrlDecoder
    }

}
