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

import io.jsonwebtoken.lang.Assert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ServiceLoader;

import static io.jsonwebtoken.lang.Collections.arrayToList;

/**
 * Helper class for loading services from the classpath, using a {@link ServiceLoader}. Decouples loading logic for
 * better separation of concerns and testability.
 */
public final class Services {

    private static final List<ClassLoaderAccessor> CLASS_LOADER_ACCESSORS = arrayToList(new ClassLoaderAccessor[] {
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

    private Services() {}

    /**
     * Loads and instantiates all service implementation of the given SPI class and returns them as a List.
     *
     * @param spi The class of the Service Provider Interface
     * @param <T> The type of the SPI
     * @return An unmodifiable list with an instance of all available implementations of the SPI. No guarantee is given
     * on the order of implementations, if more than one.
     */
    public static <T> List<T> loadAll(Class<T> spi) {
        Assert.notNull(spi, "Parameter 'spi' must not be null.");

        for (ClassLoaderAccessor classLoaderAccessor : CLASS_LOADER_ACCESSORS) {
            List<T> implementations = loadAll(spi, classLoaderAccessor.getClassLoader());
            if (!implementations.isEmpty()) {
                return Collections.unmodifiableList(implementations);
            }
        }

        throw new UnavailableImplementationException(spi);
    }

    private static <T> List<T> loadAll(Class<T> spi, ClassLoader classLoader) {
        ServiceLoader<T> serviceLoader = ServiceLoader.load(spi, classLoader);
        List<T> implementations = new ArrayList<>();
        for (T implementation : serviceLoader) {
            implementations.add(implementation);
        }
        return implementations;
    }

    /**
     * Loads the first available implementation the given SPI class from the classpath. Uses the {@link ServiceLoader}
     * to find implementations. When multiple implementations are available it will return the first one that it
     * encounters. There is no guarantee with regard to ordering.
     *
     * @param spi The class of the Service Provider Interface
     * @param <T> The type of the SPI
     * @return A new instance of the service.
     * @throws UnavailableImplementationException When no implementation the SPI is available on the classpath.
     */
    public static <T> T loadFirst(Class<T> spi) {
        Assert.notNull(spi, "Parameter 'spi' must not be null.");

        for (ClassLoaderAccessor classLoaderAccessor : CLASS_LOADER_ACCESSORS) {
            T result = loadFirst(spi, classLoaderAccessor.getClassLoader());
            if (result != null) {
                return result;
            }
        }
        throw new UnavailableImplementationException(spi);
    }

    private static <T> T loadFirst(Class<T> spi, ClassLoader classLoader) {
        ServiceLoader<T> serviceLoader = ServiceLoader.load(spi, classLoader);
        if (serviceLoader.iterator().hasNext()) {
            return serviceLoader.iterator().next();
        }
        return null;
    }

    private interface ClassLoaderAccessor {
        ClassLoader getClassLoader();
    }
}
