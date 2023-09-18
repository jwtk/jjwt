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
package io.jsonwebtoken.orgjson.io;

import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

/**
 * @since 0.10.0
 * @deprecated since JJWT_RELEASE_VERSION in favor of {@link OrgJsonWriter}
 */
@SuppressWarnings("DeprecatedIsStillUsed")
@Deprecated
public class OrgJsonSerializer<T> extends OrgJsonWriter<T> implements Serializer<T> {

    @SuppressWarnings("deprecation")
    @Override
    public byte[] serialize(T object) throws SerializationException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(256);
        Writer writer = new OutputStreamWriter(baos, StandardCharsets.UTF_8);
        try {
            write(writer, object);
        } catch (Throwable t) {
            String msg = "Unable to serialize object of type " + object.getClass().getName() +
                    " to JSON: " + t.getMessage();
            throw new SerializationException(msg, t);
        } finally {
            Objects.nullSafeClose(writer);
        }
        return baos.toByteArray();
    }

    /**
     * Serializes the specified org.json instance a byte array.
     *
     * @param o the org.json instance to serialize
     * @return the JSON byte array
     * @deprecated not called by JJWT
     */
    @Deprecated
    protected byte[] toBytes(Object o) {
        String s = super.toString(o);
        return s.getBytes(Strings.UTF_8);
    }
}
