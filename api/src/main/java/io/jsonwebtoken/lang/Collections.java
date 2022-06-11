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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public final class Collections {

    private Collections(){} //prevent instantiation

    /**
     * Return <code>true</code> if the supplied Collection is <code>null</code>
     * or empty. Otherwise, return <code>false</code>.
     * @param collection the Collection to check
     * @return whether the given Collection is empty
     */
    public static boolean isEmpty(Collection collection) {
        return (collection == null || collection.isEmpty());
    }

    /**
     * Returns the collection's size or {@code 0} if the collection is {@code null}.
     *
     * @param collection the collection to check.
     * @return the collection's size or {@code 0} if the collection is {@code null}.
     * @since 0.9.2
     */
    public static int size(Collection collection) {
        return collection == null ? 0 : collection.size();
    }

    /**
     * Returns the map's size or {@code 0} if the map is {@code null}.
     *
     * @param map the map to check
     * @return the map's size or {@code 0} if the map is {@code null}.
     * @since 0.9.2
     */
    public static int size(Map map) {
        return map == null ? 0 : map.size();
    }

    /**
     * Return <code>true</code> if the supplied Map is <code>null</code>
     * or empty. Otherwise, return <code>false</code>.
     * @param map the Map to check
     * @return whether the given Map is empty
     */
    public static boolean isEmpty(Map map) {
        return (map == null || map.isEmpty());
    }

    /**
     * Convert the supplied array into a List. A primitive array gets
     * converted into a List of the appropriate wrapper type.
     * <p>A <code>null</code> source value will be converted to an
     * empty List.
     * @param source the (potentially primitive) array
     * @return the converted List result
     * @see Objects#toObjectArray(Object)
     */
    public static List arrayToList(Object source) {
        return Arrays.asList(Objects.toObjectArray(source));
    }

    /**
     * Merge the given array into the given Collection.
     * @param array the array to merge (may be <code>null</code>)
     * @param collection the target Collection to merge the array into
     */
    @SuppressWarnings("unchecked")
    public static void mergeArrayIntoCollection(Object array, Collection collection) {
        if (collection == null) {
            throw new IllegalArgumentException("Collection must not be null");
        }
        Object[] arr = Objects.toObjectArray(array);
        for (Object elem : arr) {
            collection.add(elem);
        }
    }

    /**
     * Merge the given Properties instance into the given Map,
     * copying all properties (key-value pairs) over.
     * <p>Uses <code>Properties.propertyNames()</code> to even catch
     * default properties linked into the original Properties instance.
     * @param props the Properties instance to merge (may be <code>null</code>)
     * @param map the target Map to merge the properties into
     */
    @SuppressWarnings("unchecked")
    public static void mergePropertiesIntoMap(Properties props, Map map) {
        if (map == null) {
            throw new IllegalArgumentException("Map must not be null");
        }
        if (props != null) {
            for (Enumeration en = props.propertyNames(); en.hasMoreElements();) {
                String key = (String) en.nextElement();
                Object value = props.getProperty(key);
                if (value == null) {
                    // Potentially a non-String value...
                    value = props.get(key);
                }
                map.put(key, value);
            }
        }
    }


    /**
     * Check whether the given Iterator contains the given element.
     * @param iterator the Iterator to check
     * @param element the element to look for
     * @return <code>true</code> if found, <code>false</code> else
     */
    public static boolean contains(Iterator iterator, Object element) {
        if (iterator != null) {
            while (iterator.hasNext()) {
                Object candidate = iterator.next();
                if (Objects.nullSafeEquals(candidate, element)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check whether the given Enumeration contains the given element.
     * @param enumeration the Enumeration to check
     * @param element the element to look for
     * @return <code>true</code> if found, <code>false</code> else
     */
    public static boolean contains(Enumeration enumeration, Object element) {
        if (enumeration != null) {
            while (enumeration.hasMoreElements()) {
                Object candidate = enumeration.nextElement();
                if (Objects.nullSafeEquals(candidate, element)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check whether the given Collection contains the given element instance.
     * <p>Enforces the given instance to be present, rather than returning
     * <code>true</code> for an equal element as well.
     * @param collection the Collection to check
     * @param element the element to look for
     * @return <code>true</code> if found, <code>false</code> else
     */
    public static boolean containsInstance(Collection collection, Object element) {
        if (collection != null) {
            for (Object candidate : collection) {
                if (candidate == element) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Return <code>true</code> if any element in '<code>candidates</code>' is
     * contained in '<code>source</code>'; otherwise returns <code>false</code>.
     * @param source the source Collection
     * @param candidates the candidates to search for
     * @return whether any of the candidates has been found
     */
    public static boolean containsAny(Collection source, Collection candidates) {
        if (isEmpty(source) || isEmpty(candidates)) {
            return false;
        }
        for (Object candidate : candidates) {
            if (source.contains(candidate)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return the first element in '<code>candidates</code>' that is contained in
     * '<code>source</code>'. If no element in '<code>candidates</code>' is present in
     * '<code>source</code>' returns <code>null</code>. Iteration order is
     * {@link Collection} implementation specific.
     * @param source the source Collection
     * @param candidates the candidates to search for
     * @return the first present object, or <code>null</code> if not found
     */
    public static Object findFirstMatch(Collection source, Collection candidates) {
        if (isEmpty(source) || isEmpty(candidates)) {
            return null;
        }
        for (Object candidate : candidates) {
            if (source.contains(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    /**
     * Find a single value of the given type in the given Collection.
     * @param collection the Collection to search
     * @param type the type to look for
     * @param <T> the generic type parameter for {@code type}
     * @return a value of the given type found if there is a clear match,
     * or <code>null</code> if none or more than one such value found
     */
    @SuppressWarnings("unchecked")
    public static <T> T findValueOfType(Collection<?> collection, Class<T> type) {
        if (isEmpty(collection)) {
            return null;
        }
        T value = null;
        for (Object element : collection) {
            if (type == null || type.isInstance(element)) {
                if (value != null) {
                    // More than one value found... no clear single value.
                    return null;
                }
                value = (T) element;
            }
        }
        return value;
    }

    /**
     * Find a single value of one of the given types in the given Collection:
     * searching the Collection for a value of the first type, then
     * searching for a value of the second type, etc.
     * @param collection the collection to search
     * @param types the types to look for, in prioritized order
     * @return a value of one of the given types found if there is a clear match,
     * or <code>null</code> if none or more than one such value found
     */
    public static Object findValueOfType(Collection<?> collection, Class<?>[] types) {
        if (isEmpty(collection) || Objects.isEmpty(types)) {
            return null;
        }
        for (Class<?> type : types) {
            Object value = findValueOfType(collection, type);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    /**
     * Determine whether the given Collection only contains a single unique object.
     * @param collection the Collection to check
     * @return <code>true</code> if the collection contains a single reference or
     * multiple references to the same instance, <code>false</code> else
     */
    public static boolean hasUniqueObject(Collection collection) {
        if (isEmpty(collection)) {
            return false;
        }
        boolean hasCandidate = false;
        Object candidate = null;
        for (Object elem : collection) {
            if (!hasCandidate) {
                hasCandidate = true;
                candidate = elem;
            }
            else if (candidate != elem) {
                return false;
            }
        }
        return true;
    }

    /**
     * Find the common element type of the given Collection, if any.
     * @param collection the Collection to check
     * @return the common element type, or <code>null</code> if no clear
     * common type has been found (or the collection was empty)
     */
    public static Class<?> findCommonElementType(Collection collection) {
        if (isEmpty(collection)) {
            return null;
        }
        Class<?> candidate = null;
        for (Object val : collection) {
            if (val != null) {
                if (candidate == null) {
                    candidate = val.getClass();
                }
                else if (candidate != val.getClass()) {
                    return null;
                }
            }
        }
        return candidate;
    }

    /**
     * Marshal the elements from the given enumeration into an array of the given type.
     * Enumeration elements must be assignable to the type of the given array. The array
     * returned will be a different instance than the array given.
     * @param enumeration the collection to convert to an array
     * @param array an array instance that matches the type of array to return
     * @param <A> the element type of the array that will be created
     * @param <E> the element type contained within the enumeration.
     * @return a new array of type {@code A} that contains the elements in the specified {@code enumeration}.
     */
    public static <A,E extends A> A[] toArray(Enumeration<E> enumeration, A[] array) {
        ArrayList<A> elements = new ArrayList<A>();
        while (enumeration.hasMoreElements()) {
            elements.add(enumeration.nextElement());
        }
        return elements.toArray(array);
    }

    /**
     * Adapt an enumeration to an iterator.
     * @param enumeration the enumeration
     * @param <E> the type of elements in the enumeration
     * @return the iterator
     */
    public static <E> Iterator<E> toIterator(Enumeration<E> enumeration) {
        return new EnumerationIterator<E>(enumeration);
    }

    /**
     * Iterator wrapping an Enumeration.
     */
    private static class EnumerationIterator<E> implements Iterator<E> {

        private Enumeration<E> enumeration;

        public EnumerationIterator(Enumeration<E> enumeration) {
            this.enumeration = enumeration;
        }

        public boolean hasNext() {
            return this.enumeration.hasMoreElements();
        }

        public E next() {
            return this.enumeration.nextElement();
        }

        public void remove() throws UnsupportedOperationException {
            throw new UnsupportedOperationException("Not supported");
        }
    }
}

