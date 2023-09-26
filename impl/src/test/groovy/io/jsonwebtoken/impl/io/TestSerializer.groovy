/*
 * Copyright © 2023 jsonwebtoken.io
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
package io.jsonwebtoken.impl.io

import io.jsonwebtoken.io.SerializationException
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings

import static org.junit.Assert.fail

class TestSerializer implements Serializer<Map<String, ?>> {

    Throwable ex

    @Override
    byte[] serialize(Map<String, ?> stringMap) throws SerializationException {
        fail("serialize(byte[]) should not be invoked.")
        return null
    }

    @Override
    void serialize(Map<String, ?> map, OutputStream out) throws SerializationException {
        def json = toJson(map)
        if (Strings.hasText(json)) {
            out.write(Strings.utf8(json))
        } else {
            Throwable t = ex != null ? ex : new UnsupportedOperationException("Override toJson")
            throw t
        }
    }

    protected String toJson(Map<String, ?> m) {
        return null
    }
}
