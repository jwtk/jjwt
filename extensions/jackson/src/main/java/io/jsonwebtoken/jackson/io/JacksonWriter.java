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
package io.jsonwebtoken.jackson.io;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.jsonwebtoken.lang.Assert;

import java.io.IOException;
import java.io.Writer;

public class JacksonWriter<T> implements io.jsonwebtoken.io.Writer<T> {

    static final String MODULE_ID = "jjwt-jackson";
    static final Module MODULE;

    static {
        SimpleModule module = new SimpleModule(MODULE_ID);
        module.addSerializer(JacksonSupplierSerializer.INSTANCE);
        MODULE = module;
    }

    static final ObjectMapper DEFAULT_OBJECT_MAPPER = new ObjectMapper().registerModule(MODULE);

    protected final ObjectMapper objectMapper;

    /**
     * Constructor using JJWT's default {@link ObjectMapper} singleton for serialization.
     */
    public JacksonWriter() {
        this(DEFAULT_OBJECT_MAPPER);
    }

    /**
     * Creates a new Jackson Serializer that uses the specified {@link ObjectMapper} for serialization.
     *
     * @param objectMapper the ObjectMapper to use for serialization.
     */
    public JacksonWriter(ObjectMapper objectMapper) {
        Assert.notNull(objectMapper, "ObjectMapper cannot be null.");
        this.objectMapper = objectMapper.registerModule(MODULE);
    }

    @Override
    public void write(Writer out, T t) throws IOException {
        Assert.notNull(out, "Writer cannot be null.");
        writeValue(t, out);
    }

    protected void writeValue(T t, Writer writer) throws java.io.IOException {
        this.objectMapper.writeValue(writer, t);
    }
}
