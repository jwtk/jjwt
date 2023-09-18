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

import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.io.Writer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

import java.io.IOException;
import java.util.Map;

public class SerializingMapWriter implements Writer<Map<String, ?>> {

    private final Serializer<Map<String, ?>> DELEGATE;

    public SerializingMapWriter(Serializer<Map<String, ?>> delegate) {
        this.DELEGATE = Assert.notNull(delegate, "Serializer cannot be null.");
    }

    @Override
    public void write(java.io.Writer out, Map<String, ?> map) throws IOException {
        byte[] bytes = DELEGATE.serialize(map);
        String s = Strings.utf8(bytes);
        out.write(s);
    }
}
