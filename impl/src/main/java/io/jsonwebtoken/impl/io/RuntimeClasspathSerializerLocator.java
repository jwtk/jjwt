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
package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import java.util.concurrent.atomic.AtomicReference;

/**
 * @since 0.10.0
 */
public class RuntimeClasspathSerializerLocator implements InstanceLocator<Serializer> {

    private static final AtomicReference<Serializer<Object>> SERIALIZER = new AtomicReference<>();

    @SuppressWarnings("unchecked")
    @Override
    public Serializer<Object> getInstance() {
        Serializer<Object> serializer = SERIALIZER.get();
        if (serializer == null) {
            serializer = locate();
            Assert.state(serializer != null, "locate() cannot return null.");
            if (!compareAndSet(serializer)) {
                serializer = SERIALIZER.get();
            }
        }
        Assert.state(serializer != null, "serializer cannot be null.");
        return serializer;
    }

    @SuppressWarnings("WeakerAccess") //to allow testing override
    protected Serializer<Object> locate() {
        if (isAvailable("io.jsonwebtoken.jackson.io.JacksonSerializer")) {
            return Classes.newInstance("io.jsonwebtoken.jackson.io.JacksonSerializer");
        } else if (isAvailable("io.jsonwebtoken.orgjson.io.OrgJsonSerializer")) {
            return Classes.newInstance("io.jsonwebtoken.orgjson.io.OrgJsonSerializer");
        } else if (isAvailable("io.jsonwebtoken.gson.io.GsonSerializer")) {
            return Classes.newInstance("io.jsonwebtoken.gson.io.GsonSerializer");
        } else {
            throw new IllegalStateException("Unable to discover any JSON Serializer implementations on the classpath.");
        }
    }

    @SuppressWarnings("WeakerAccess") //to allow testing override
    protected boolean compareAndSet(Serializer<Object> s) {
        return SERIALIZER.compareAndSet(null, s);
    }

    @SuppressWarnings("WeakerAccess") //to allow testing override
    protected boolean isAvailable(String fqcn) {
        return Classes.isAvailable(fqcn);
    }
}
