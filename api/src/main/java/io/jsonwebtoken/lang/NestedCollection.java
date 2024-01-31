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

/**
 * A {@link CollectionMutator} that can return access to its parent via the {@link Conjunctor#and() and()} method for
 * continued configuration.  For example:
 * <blockquote><pre>
 * builder
 *     .aNestedCollection()// etc...
 *     <b>.and() // return parent</b>
 * // resume parent configuration...</pre></blockquote>
 *
 * @param <E> the type of elements in the collection
 * @param <P> the parent to return
 * @since 0.12.0
 */
public interface NestedCollection<E, P> extends CollectionMutator<E, NestedCollection<E, P>>, Conjunctor<P> {
}
