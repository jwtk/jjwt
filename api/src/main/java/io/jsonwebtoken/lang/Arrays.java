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
 * Utility methods to work with array instances.
 *
 * @since 0.6
 */
public final class Arrays {

    private Arrays() {
    } //prevent instantiation

    /**
     * Returns the length of the array, or {@code 0} if the array is {@code null}.
     *
     * @param a   the possibly-null array
     * @param <T> the type of elements in the array
     * @return the length of the array, or zero if the array is null.
     */
    public static <T> int length(T[] a) {
        return a == null ? 0 : a.length;
    }

    /**
     * Converts the specified array to a {@link List}. If the array is empty, an empty list will be returned.
     *
     * @param a   the array to represent as a list
     * @param <T> the type of elements in the array
     * @return the array as a list, or an empty list if the array is empty.
     */
    public static <T> List<T> asList(T[] a) {
        return Objects.isEmpty(a) ? Collections.<T>emptyList() : java.util.Arrays.asList(a);
    }

    /**
     * Returns the length of the specified byte array, or {@code 0} if the byte array is {@code null}.
     *
     * @param bytes the array to check
     * @return the length of the specified byte array, or {@code 0} if the byte array is {@code null}.
     */
    public static int length(byte[] bytes) {
        return bytes != null ? bytes.length : 0;
    }

    /**
     * Returns the byte array unaltered if it is non-null and has a positive length, otherwise {@code null}.
     *
     * @param bytes the byte array to check.
     * @return the byte array unaltered if it is non-null and has a positive length, otherwise {@code null}.
     */
    public static byte[] clean(byte[] bytes) {
        return length(bytes) > 0 ? bytes : null;
    }

    /**
     * Creates a shallow copy of the specified object or array.
     *
     * @param obj the object to copy
     * @return a shallow copy of the specified object or array.
     */
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
