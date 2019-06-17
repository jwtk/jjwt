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

import java.util.Iterator;
import java.util.ServiceLoader;
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

    @SuppressWarnings({"unchecked", "WeakerAccess"}) //to allow testing override
    protected Serializer<Object> locate() {
        ServiceLoader<Serializer> serviceLoader = ServiceLoader.load(Serializer.class);
        Iterator<Serializer> iterator = serviceLoader.iterator();
        if(iterator.hasNext()) {
            return  (Serializer<Object>)iterator.next();
        } else {
            throw new IllegalStateException("Unable to discover any JSON Serializer implementations on the classpath.");
        }
    }

    @SuppressWarnings("WeakerAccess") //to allow testing override
    protected boolean compareAndSet(Serializer<Object> s) {
        return SERIALIZER.compareAndSet(null, s);
    }
}
