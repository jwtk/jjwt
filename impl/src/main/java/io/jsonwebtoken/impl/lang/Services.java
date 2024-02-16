/*
 * Copyright (C) 2019 jsonwebtoken.io
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
package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;

import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Helper class for loading services from the classpath, using a {@link ServiceLoader}. Decouples loading logic for
 * better separation of concerns and testability.
 */
public final class Services {

    private static final ConcurrentMap<Class<?>, Object> SERVICES = new ConcurrentHashMap<>();

    private static final List<ClassLoaderAccessor> CLASS_LOADER_ACCESSORS = Arrays.asList(new ClassLoaderAccessor[]{
            new ClassLoaderAccessor() {
                @Override
                public ClassLoader getClassLoader() {
                    return Thread.currentThread().getContextClassLoader();
                }
            },
            new ClassLoaderAccessor() {
                @Override
                public ClassLoader getClassLoader() {
                    return Services.class.getClassLoader();
                }
            },
            new ClassLoaderAccessor() {
                @Override
                public ClassLoader getClassLoader() {
                    return ClassLoader.getSystemClassLoader();
                }
            }
    });

    private Services() {
    }

    /**
     * Returns the first available implementation for the given SPI class, checking an internal thread-safe cache first,
     * and, if not found, using a {@link ServiceLoader} to find implementations. When multiple implementations are
     * available it will return the first one that it encounters. There is no guarantee with regard to ordering.
     *
     * @param spi The class of the Service Provider Interface
     * @param <T> The type of the SPI
     * @return The first available instance of the service.
     * @throws UnavailableImplementationException When no implementation of the SPI class can be found.
     * @since 0.12.4
     */
    public static <T> T get(Class<T> spi) {
        // TODO: JDK8, replace this find/putIfAbsent logic with ConcurrentMap.computeIfAbsent
        T instance = findCached(spi);
        if (instance == null) {
            instance = loadFirst(spi); // throws UnavailableImplementationException if not found, which is what we want
            SERVICES.putIfAbsent(spi, instance); // cache if not already cached
        }
        return instance;
    }

    private static <T> T findCached(Class<T> spi) {
        Assert.notNull(spi, "Service interface cannot be null.");
        Object obj = SERVICES.get(spi);
        if (obj != null) {
            return Assert.isInstanceOf(spi, obj, "Unexpected cached service implementation type.");
        }
        return null;
    }

    private static <T> T loadFirst(Class<T> spi) {
        for (ClassLoaderAccessor accessor : CLASS_LOADER_ACCESSORS) {
            ServiceLoader<T> loader = ServiceLoader.load(spi, accessor.getClassLoader());
            Assert.stateNotNull(loader, "JDK ServiceLoader#load should never return null.");
            Iterator<T> i = loader.iterator();
            Assert.stateNotNull(i, "JDK ServiceLoader#iterator() should never return null.");
            if (i.hasNext()) {
                return i.next();
            }
        }
        throw new UnavailableImplementationException(spi);
    }

    /**
     * Clears internal cache of service singletons. This is useful when testing, or for applications that dynamically
     * change classloaders.
     */
    public static void reload() {
        SERVICES.clear();
    }

    private interface ClassLoaderAccessor {
        ClassLoader getClassLoader();
    }
}
