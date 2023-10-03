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
package io.jsonwebtoken.lang;

import java.util.Collection;

/**
 * Mutation (modifications) to a {@link java.util.Collection} instance while also supporting method chaining. The
 * {@link Collection#add(Object)}, {@link Collection#addAll(Collection)}, {@link Collection#remove(Object)}, and
 * {@link Collection#clear()} methods do not support method chaining, so this interface enables that behavior.
 *
 * @param <E> the type of elements in the collection
 * @param <M> the mutator subtype, for method chaining
 * @since 0.12.0
 */
public interface CollectionMutator<E, M extends CollectionMutator<E, M>> {

    /**
     * Adds the specified element to the collection.
     *
     * @param e the element to add.
     * @return the mutator/builder for method chaining.
     */
    M add(E e);

    /**
     * Adds the elements to the collection in iteration order.
     *
     * @param c the collection to add
     * @return the mutator/builder for method chaining.
     */
    M add(Collection<? extends E> c);

    /**
     * Removes all elements in the collection.
     *
     * @return the mutator/builder for method chaining.
     */
    M clear();

    /**
     * Removes the specified element from the collection.
     *
     * @param e the element to remove.
     * @return the mutator/builder for method chaining.
     */
    M remove(E e);
}
