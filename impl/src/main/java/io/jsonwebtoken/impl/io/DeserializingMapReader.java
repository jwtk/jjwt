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
package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.io.Reader;
import io.jsonwebtoken.lang.Assert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class DeserializingMapReader implements Reader<Map<String, ?>> {

    private final Deserializer<Map<String, ?>> deserializer;

    public DeserializingMapReader(Deserializer<Map<String, ?>> deserializer) {
        this.deserializer = Assert.notNull(deserializer, "Deserializer cannot be null.");
    }

    @Override
    public Map<String, ?> read(java.io.Reader in) throws IOException {
        int len = 256;
        ByteArrayOutputStream baos = new ByteArrayOutputStream(len);
        try (OutputStreamWriter writer = new OutputStreamWriter(baos, StandardCharsets.UTF_8)) {
            char[] buf = new char[len];
            while (len != -1) {
                len = in.read(buf, 0, buf.length);
                if (len > 0) writer.write(buf, 0, len);
            }
        }
        byte[] data = baos.toByteArray();
        return deserializer.deserialize(data);
    }
}
