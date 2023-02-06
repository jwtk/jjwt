/*
 * Copyright © 2020 jsonwebtoken.io
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
import io.jsonwebtoken.lang.Collections;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

class CollectionConverter<T, C extends Collection<T>> implements Converter<C, Object> {

    private final Converter<T, Object> elementConverter;
    private final Function<Integer, C> fn;

    public static <T> CollectionConverter<T, List<T>> forList(Converter<T,Object> elementConverter) {
        return new CollectionConverter<>(elementConverter, new CreateListFunction<T>());
    }

    public static <T> CollectionConverter<T, Set<T>> forSet(Converter<T, Object> elementConverter) {
        return new CollectionConverter<>(elementConverter, new CreateSetFunction<T>());
    }

    public CollectionConverter(Converter<T, Object> elementConverter, Function<Integer, C> fn) {
        this.elementConverter = Assert.notNull(elementConverter, "Element converter cannot be null.");
        this.fn = Assert.notNull(fn, "Collection function cannot be null.");
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public Object applyTo(C ts) {
        if (Collections.isEmpty(ts)) {
            return ts;
        }
        Collection c = fn.apply(ts.size());
        for (T element : ts) {
            Object encoded = elementConverter.applyTo(element);
            c.add(encoded);
        }
        return c;
    }

    private C toElementList(Collection<?> c) {
        Assert.notEmpty(c, "Collection cannot be null or empty.");
        C result = fn.apply(c.size());
        for (Object o : c) {
            T element = elementConverter.applyFrom(o);
            result.add(element);
        }
        return result;
    }

    @Override
    public C applyFrom(Object value) {
        if (value == null) {
            return null;
        }
        Collection<?> c;
        if (value.getClass().isArray() && !value.getClass().getComponentType().isPrimitive()) {
            c = Collections.arrayToList(value);
        } else if (value instanceof Collection) {
            c = (Collection<?>) value;
        } else {
            c = java.util.Collections.singletonList(value);
        }
        C result;
        if (Collections.isEmpty(c)) {
            result = fn.apply(0);
        } else {
            result = toElementList(c);
        }
        return result;
    }

    private static class CreateListFunction<A> implements Function<Integer, List<A>> {
        @Override
        public List<A> apply(Integer size) {
            return size > 0 ? new ArrayList<A>(size) : new ArrayList<A>();
        }
    }

    private static class CreateSetFunction<T> implements Function<Integer, Set<T>> {
        @Override
        public Set<T> apply(Integer size) {
            return size > 0 ? new LinkedHashSet<T>(size) : new LinkedHashSet<T>();
        }
    }
}
