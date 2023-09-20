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
package io.jsonwebtoken.impl

import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.impl.security.Randoms
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.io.Reader

class RfcTests {

    static String encode(byte[] b) {
        return Encoders.BASE64URL.encode(b)
    }

    static byte[] decode(String val) {
        return Decoders.BASE64URL.decode(val)
    }

    static final String stripws(String s) {
        return s.replaceAll('[\\s]', '')
    }

    static final Map<String, ?> jsonToMap(String json) {
        return Services.loadFirst(Reader).read(new StringReader(json)) as Map<String, ?>
    }

    /**
     * Returns a random string useful as a test value NOT to be used as a cryptographic key.
     * @return a random string useful as a test value NOT to be used as a cryptographic key.
     */
    static String srandom() {
        byte[] random = new byte[16]
        Randoms.secureRandom().nextBytes(random)
        return Encoders.BASE64URL.encode(random)
    }
}
