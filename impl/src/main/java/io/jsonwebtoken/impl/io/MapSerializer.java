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

import io.jsonwebtoken.impl.lang.BiConsumer;
import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Writer;
import io.jsonwebtoken.lang.Assert;

import java.util.Map;

public class MapSerializer implements BiConsumer<java.io.Writer, Map<String, ?>> {

    private final Writer<Map<String, ?>> DELEGATE;
    private final String name;

    public MapSerializer(Writer<Map<String, ?>> jsonWriter, String name) {
        this.DELEGATE = Assert.notNull(jsonWriter, "JSON Writer cannot be null.");
        this.name = Assert.hasText(name, "Name cannot be null or empty.");
    }

    @Override
    public void accept(java.io.Writer writer, Map<String, ?> map) {
        try {
            this.DELEGATE.write(writer, map);
        } catch (Throwable t) {
            String msg = String.format("Cannot serialize %s to JSON. Cause: %s", name, t.getMessage());
            throw new SerializationException(msg, t);
        }
    }
}
