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

import io.jsonwebtoken.io.AbstractSerializer;
import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Assert;

import java.io.OutputStream;
import java.util.Map;

public class NamedSerializer extends AbstractSerializer<Map<String, ?>> {

    private final String name;
    private final Serializer<Map<String, ?>> DELEGATE;

    public NamedSerializer(String name, Serializer<Map<String, ?>> serializer) {
        this.DELEGATE = Assert.notNull(serializer, "JSON Serializer cannot be null.");
        this.name = Assert.hasText(name, "Name cannot be null or empty.");
    }

    @Override
    protected void doSerialize(Map<String, ?> m, OutputStream out) throws SerializationException {
        try {
            this.DELEGATE.serialize(m, out);
        } catch (Throwable t) {
            String msg = String.format("Cannot serialize %s to JSON. Cause: %s", this.name, t.getMessage());
            throw new SerializationException(msg, t);
        }
    }
}
