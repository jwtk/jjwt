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

import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Objects;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;

/**
 * @since 0.10.0
 * @deprecated since JJWT_RELEASE_VERSION in favor of {@link OrgJsonReader}
 */
@SuppressWarnings("DeprecatedIsStillUsed")
@Deprecated
public class OrgJsonDeserializer extends OrgJsonReader implements Deserializer<Object> {

    @SuppressWarnings("deprecation")
    @Override
    public Object deserialize(byte[] bytes) throws DeserializationException {
        if (Objects.isEmpty(bytes)) {
            throw new DeserializationException("Invalid JSON: null or zero length byte array.");
        }
        Reader reader = new InputStreamReader(new ByteArrayInputStream(bytes), StandardCharsets.UTF_8);
        try {
            return read(reader);
        } catch (Throwable t) {
            String msg = "Unable to deserialize JSON bytes: " + t.getMessage();
            throw new DeserializationException(msg, t);
        } finally {
            Objects.nullSafeClose(reader);
        }
    }
}
