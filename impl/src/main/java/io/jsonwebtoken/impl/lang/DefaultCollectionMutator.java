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
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.CollectionMutator;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.NoSuchElementException;

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

    public M replace(E existingElement, E newElement) {
        Assert.notEmpty(existingElement, "existingElement cannot be null or empty.");
        Assert.notEmpty(newElement, "newElement cannot be null or empty.");

        // Same item, nothing to do
        if (existingElement.equals(newElement))
            return self();

        // Does not contain existingElement to replace
        if (!this.collection.contains(existingElement)) {
            String msg = this.getClass() + " does not contain " + existingElement + ".";
            throw new NoSuchElementException(msg);
        }

        // Replacement step 1: iterate until element to replace
        Iterator<E> it = this.collection.iterator();
        while (it.hasNext())
            if (it.next().equals(existingElement)) {
                it.remove(); // step 2: remove existingElement
                break;
            }

        // Replacement step 3: collect and remove elements after element to replace
        Collection<E> elementsAfterExisting = new LinkedHashSet<>();
        while (it.hasNext()) {
            elementsAfterExisting.add(it.next());
            it.remove();
        }

        this.doAdd(newElement); // step 4: add replacer element (position will be at the existingElement)
        this.collection.addAll(elementsAfterExisting); // step 5: add back the elemnts found after existingElement

        changed(); // trigger changed()

        return self();
    }

    @Override
    public M add(E e) {
        E existing = null;
        for (E item : collection) {
            boolean bothIdentifiable = e instanceof Identifiable && item instanceof Identifiable;
            boolean sameId = bothIdentifiable && ((Identifiable) item).getId().equals(((Identifiable) e).getId());
            if (sameId) {
                existing = item;
                break;
            }
        }

        if (Objects.isEmpty(existing)) {
            if (doAdd(e)) changed();
        }
        else replace(existing, e);

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
