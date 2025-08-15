/*
 * Copyright © 2025 jsonwebtoken.io
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
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.NestedCollection;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @param <E> the type of Identifiable elements in the collection
 * @param <P> the parent to return
 * @since 0.12.7
 */
public class NestedIdentifiableCollection<E extends Identifiable, P> implements NestedCollection<E, P> {

    private final P PARENT;
    private final Map<String, E> VALUES;

    private static <K, V> Map<K, V> nullSafe(Map<K, V> m) {
        return m == null ? Collections.<K, V>emptyMap() : m;
    }

    public NestedIdentifiableCollection(P parent, Map<String, ? extends E> seed) {
        super();
        this.PARENT = Assert.notNull(parent, "parent cannot be null.");
        this.VALUES = new LinkedHashMap<>(nullSafe(seed));
    }

    protected final String assertId(E i) {
        Assert.notNull(i, "Identifiable instance cannot be null.");
        String id = i.getId();
        if (!Strings.hasText(id)) {
            String msg = i.getClass() + " getId() cannot be null or empty.";
            throw new IllegalArgumentException(msg);
        }
        return id;
    }

    private boolean doAdd(E e) {
        String id = assertId(e);
        this.VALUES.put(id, e);
        return true;
    }

    @Override
    public NestedCollection<E, P> add(E e) {
        if (e != null) {
            doAdd(e);
            changed();
        }
        return this;
    }

    @Override
    public NestedCollection<E, P> remove(E e) {
        if (e != null) {
            String id = assertId(e);
            E previous = this.VALUES.remove(id);
            if (previous != null) changed();
        }
        return this;
    }

    @Override
    public NestedCollection<E, P> clear() {
        if (!Collections.isEmpty(this.VALUES)) {
            this.VALUES.clear();
            changed();
        }
        return this;
    }

    @Override
    public NestedCollection<E, P> add(Collection<? extends E> c) {
        boolean changed = false;
        for (E element : Collections.nullSafe(c)) {
            changed = doAdd(element) || changed;
        }
        if (changed) changed();
        return this;
    }

    @Override
    public P and() {
        return this.PARENT;
    }

    protected void changed() {
    }

    protected final Map<String, E> getValues() {
        return Collections.immutable(this.VALUES);
    }
}
