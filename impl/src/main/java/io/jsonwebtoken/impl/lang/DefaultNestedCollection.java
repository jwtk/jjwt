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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.NestedCollection;

import java.util.Collection;

public class DefaultNestedCollection<E, P> extends DefaultCollectionMutator<E, NestedCollection<E, P>>
        implements NestedCollection<E, P> {

    private final P parent;

    public DefaultNestedCollection(P parent, Collection<? extends E> seed) {
        super(seed);
        this.parent = Assert.notNull(parent, "Parent cannot be null.");
    }

    @Override
    public P and() {
        return this.parent;
    }
}
