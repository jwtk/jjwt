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
package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.lang.CollectionMutator;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;
import java.util.LinkedHashSet;

public class DefaultCollectionMutator<E, M extends CollectionMutator<E, M>> implements CollectionMutator<E, M> {

    private final Collection<E> collection;

    public DefaultCollectionMutator(Collection<? extends E> seed) {
        this.collection = new LinkedHashSet<>(Collections.nullSafe(seed));
    }

    @SuppressWarnings("unchecked")
    protected final M self() {
        return (M) this;
    }

    @Override
    public M add(E e) {
        if (Objects.isEmpty(e)) return self();
        if (e instanceof Identifiable && !Strings.hasText(((Identifiable) e).getId())) {
            String msg = e.getClass() + " getId() value cannot be null or empty.";
            throw new IllegalArgumentException(msg);
        }
        this.collection.remove(e);
        this.collection.add(e);
        return self();
    }

    @Override
    public M remove(E e) {
        this.collection.remove(e);
        return self();
    }

    @Override
    public M add(Collection<? extends E> c) {
        for (E element : Collections.nullSafe(c)) {
            add(element);
        }
        return self();
    }

    @Override
    public M clear() {
        this.collection.clear();
        return self();
    }

    protected Collection<E> getCollection() {
        return Collections.immutable(this.collection);
    }
}
