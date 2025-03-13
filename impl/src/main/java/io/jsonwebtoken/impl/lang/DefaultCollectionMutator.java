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
import java.util.Iterator;
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

    private boolean doAdd(E e) {
        if (Objects.isEmpty(e)) return false;
        if (e instanceof Identifiable && !Strings.hasText(((Identifiable) e).getId())) {
            String msg = e.getClass() + " getId() value cannot be null or empty.";
            throw new IllegalArgumentException(msg);
        }
        return this.collection.add(e);
    }

    @Override
    public M add(E e) {
        boolean doReplace = false;

        // Replacement step 1: iterate until element to replace (if any)
        E item;
        Iterator<E> it = this.collection.iterator();
        while (it.hasNext()) {
            item = it.next();

            // Same item, nothing to do
            if (item.equals(e))
                return self();

            boolean bothIdentifiable = e instanceof Identifiable && item instanceof Identifiable;
            boolean sameId = bothIdentifiable && ((Identifiable) item).getId().equals(((Identifiable) e).getId());
            if (sameId) {
                it.remove(); // step 2: remove existing item
                doReplace = true;
                break;
            }
        }

        if (doReplace) {
            // Replacement step 3: collect and remove elements after element to replace
            Collection<E> elementsAfterExisting = new LinkedHashSet<>();
            while (it.hasNext()) {
                elementsAfterExisting.add(it.next());
                it.remove();
            }

            this.doAdd(e); // step 4: add replacer element (position will be at the existing item)
            this.collection.addAll(elementsAfterExisting); // step 5: add back the elements found after existing item

            changed(); // trigger changed()
        }
        else {
            // No replacement, do add instead
            if (doAdd(e)) changed();
        }

        return self();
    }

    @Override
    public M remove(E e) {
        if (this.collection.remove(e)) changed();
        return self();
    }

    @Override
    public M add(Collection<? extends E> c) {
        boolean changed = false;
        for (E element : Collections.nullSafe(c)) {
            changed = doAdd(element) || changed;
        }
        if (changed) changed();
        return self();
    }

    @Override
    public M clear() {
        boolean changed = !Collections.isEmpty(this.collection);
        this.collection.clear();
        if (changed) changed();
        return self();
    }

    /**
     * Callback for subclasses that wish to be notified if the internal collection has changed via builder mutation
     * methods.
     */
    protected void changed() {
    }

    protected Collection<E> getCollection() {
        return Collections.immutable(this.collection);
    }
}
