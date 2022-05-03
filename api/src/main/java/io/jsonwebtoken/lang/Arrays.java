/*
 * Copyright (C) 2014 jsonwebtoken.io
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

import java.lang.reflect.Array;
import java.util.List;

/**
 * @since 0.6
 */
public final class Arrays {

    private Arrays() {
    } //prevent instantiation

    public static <T> int length(T[] a) {
        return a == null ? 0 : a.length;
    }

    public static <T> List<T> asList(T[] a) {
        return Objects.isEmpty(a) ? Collections.<T>emptyList() : java.util.Arrays.asList(a);
    }

    public static int length(byte[] bytes) {
        return bytes != null ? bytes.length : 0;
    }

    public static byte[] clean(byte[] bytes) {
        return length(bytes) > 0 ? bytes : null;
    }

    public static Object copy(Object obj) {
        if (obj == null) {
            return null;
        }
        Assert.isTrue(Objects.isArray(obj), "Argument must be an array.");
        if (obj instanceof Object[]) {
            return ((Object[]) obj).clone();
        }
        if (obj instanceof boolean[]) {
            return ((boolean[]) obj).clone();
        }
        if (obj instanceof byte[]) {
            return ((byte[]) obj).clone();
        }
        if (obj instanceof char[]) {
            return ((char[]) obj).clone();
        }
        if (obj instanceof double[]) {
            return ((double[]) obj).clone();
        }
        if (obj instanceof float[]) {
            return ((float[]) obj).clone();
        }
        if (obj instanceof int[]) {
            return ((int[]) obj).clone();
        }
        if (obj instanceof long[]) {
            return ((long[]) obj).clone();
        }
        if (obj instanceof short[]) {
            return ((short[]) obj).clone();
        }
        Class<?> componentType = obj.getClass().getComponentType();
        int length = Array.getLength(obj);
        Object[] copy = (Object[]) Array.newInstance(componentType, length);
        for (int i = 0; i < length; i++) {
            copy[i] = Array.get(obj, i);
        }
        return copy;
    }
}
