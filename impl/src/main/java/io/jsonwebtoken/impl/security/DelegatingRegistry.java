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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Registry;

import java.util.Collection;

abstract class DelegatingRegistry<T> implements Registry<String, T> {

    private final Registry<String, T> REGISTRY;

    protected DelegatingRegistry(Registry<String, T> registry) {
        this.REGISTRY = Assert.notNull(registry, "Registry cannot be null.");
        Assert.notEmpty(this.REGISTRY.values(), "Registry cannot be empty.");
    }

    @Override
    public int size() {
        return REGISTRY.size();
    }

    @Override
    public Collection<T> values() {
        return REGISTRY.values();
    }

    @Override
    public T forKey(String id) throws IllegalArgumentException {
        return REGISTRY.forKey(id);
    }

    @Override
    public T get(Object id) {
        return REGISTRY.get(id);
    }
}
