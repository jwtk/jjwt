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

import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;

import java.util.Iterator;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @since 0.10.0
 */
public class RuntimeClasspathDeserializerLocator<T> implements InstanceLocator<Deserializer<T>> {

    private static final AtomicReference<Deserializer> DESERIALIZER = new AtomicReference<>();

    @SuppressWarnings("unchecked")
    @Override
    public Deserializer<T> getInstance() {
        Deserializer<T> deserializer = DESERIALIZER.get();
        if (deserializer == null) {
            deserializer = locate();
            Assert.state(deserializer != null, "locate() cannot return null.");
            if (!compareAndSet(deserializer)) {
                deserializer = DESERIALIZER.get();
            }
        }
        Assert.state(deserializer != null, "deserializer cannot be null.");
        return deserializer;
    }

    @SuppressWarnings("WeakerAccess") //to allow testing override
    protected Deserializer<T> locate() {
        ServiceLoader<Deserializer> serviceLoader = ServiceLoader.load(Deserializer.class);
        Iterator<Deserializer> iterator = serviceLoader.iterator();
        if(iterator.hasNext()) {
            return  (Deserializer<T>)iterator.next();
        } else {
            throw new IllegalStateException("Unable to discover any JSON Deserializer implementations on the classpath.");
        }
    }

    @SuppressWarnings("WeakerAccess") //to allow testing override
    protected boolean compareAndSet(Deserializer<T> d) {
        return DESERIALIZER.compareAndSet(null, d);
    }
}
