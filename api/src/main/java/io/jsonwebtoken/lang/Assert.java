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

import java.util.Collection;
import java.util.Map;

/**
 * Utility methods for providing argument and state assertions to reduce repeating these patterns and otherwise
 * increasing cyclomatic complexity.
 */
public final class Assert {

    private Assert() {
    } //prevent instantiation

    /**
     * Assert a boolean expression, throwing <code>IllegalArgumentException</code>
     * if the test result is <code>false</code>.
     * <pre class="code">Assert.isTrue(i &gt; 0, "The value must be greater than zero");</pre>
     *
     * @param expression a boolean expression
     * @param message    the exception message to use if the assertion fails
     * @throws IllegalArgumentException if expression is <code>false</code>
     */
    public static void isTrue(boolean expression, String message) {
        if (!expression) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * Assert a boolean expression, throwing <code>IllegalArgumentException</code>
     * if the test result is <code>false</code>.
     * <pre class="code">Assert.isTrue(i &gt; 0);</pre>
     *
     * @param expression a boolean expression
     * @throws IllegalArgumentException if expression is <code>false</code>
     */
    public static void isTrue(boolean expression) {
        isTrue(expression, "[Assertion failed] - this expression must be true");
    }

    /**
     * Assert that an object is <code>null</code> .
     * <pre class="code">Assert.isNull(value, "The value must be null");</pre>
     *
     * @param object  the object to check
     * @param message the exception message to use if the assertion fails
     * @throws IllegalArgumentException if the object is not <code>null</code>
     */
    public static void isNull(Object object, String message) {
        if (object != null) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * Assert that an object is <code>null</code> .
     * <pre class="code">Assert.isNull(value);</pre>
     *
     * @param object the object to check
     * @throws IllegalArgumentException if the object is not <code>null</code>
     */
    public static void isNull(Object object) {
        isNull(object, "[Assertion failed] - the object argument must be null");
    }

    /**
     * Assert that an object is not <code>null</code> .
     * <pre class="code">Assert.notNull(clazz, "The class must not be null");</pre>
     *
     * @param object  the object to check
     * @param <T>     the type of object
     * @param message the exception message to use if the assertion fails
     * @return the non-null object
     * @throws IllegalArgumentException if the object is <code>null</code>
     */
    public static <T> T notNull(T object, String message) {
        if (object == null) {
            throw new IllegalArgumentException(message);
        }
        return object;
    }

    /**
     * Assert that an object is not <code>null</code> .
     * <pre class="code">Assert.notNull(clazz);</pre>
     *
     * @param object the object to check
     * @throws IllegalArgumentException if the object is <code>null</code>
     */
    public static void notNull(Object object) {
        notNull(object, "[Assertion failed] - this argument is required; it must not be null");
    }

    /**
     * Assert that the given String is not empty; that is,
     * it must not be <code>null</code> and not the empty String.
     * <pre class="code">Assert.hasLength(name, "Name must not be empty");</pre>
     *
     * @param text    the String to check
     * @param message the exception message to use if the assertion fails
     * @see Strings#hasLength
     */
    public static void hasLength(String text, String message) {
        if (!Strings.hasLength(text)) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * Assert that the given String is not empty; that is,
     * it must not be <code>null</code> and not the empty String.
     * <pre class="code">Assert.hasLength(name);</pre>
     *
     * @param text the String to check
     * @see Strings#hasLength
     */
    public static void hasLength(String text) {
        hasLength(text,
                "[Assertion failed] - this String argument must have length; it must not be null or empty");
    }

    /**
     * Assert that the given String has valid text content; that is, it must not
     * be <code>null</code> and must contain at least one non-whitespace character.
     * <pre class="code">Assert.hasText(name, "'name' must not be empty");</pre>
     *
     * @param text    the String to check
     * @param message the exception message to use if the assertion fails
     * @return the string if it has text
     * @see Strings#hasText
     */
    public static String hasText(String text, String message) {
        if (!Strings.hasText(text)) {
            throw new IllegalArgumentException(message);
        }
        return text;
    }

    /**
     * Assert that the given String has valid text content; that is, it must not
     * be <code>null</code> and must contain at least one non-whitespace character.
     * <pre class="code">Assert.hasText(name, "'name' must not be empty");</pre>
     *
     * @param text the String to check
     * @see Strings#hasText
     */
    public static void hasText(String text) {
        hasText(text,
                "[Assertion failed] - this String argument must have text; it must not be null, empty, or blank");
    }

    /**
     * Assert that the given text does not contain the given substring.
     * <pre class="code">Assert.doesNotContain(name, "rod", "Name must not contain 'rod'");</pre>
     *
     * @param textToSearch the text to search
     * @param substring    the substring to find within the text
     * @param message      the exception message to use if the assertion fails
     */
    public static void doesNotContain(String textToSearch, String substring, String message) {
        if (Strings.hasLength(textToSearch) && Strings.hasLength(substring) &&
                textToSearch.indexOf(substring) != -1) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * Assert that the given text does not contain the given substring.
     * <pre class="code">Assert.doesNotContain(name, "rod");</pre>
     *
     * @param textToSearch the text to search
     * @param substring    the substring to find within the text
     */
    public static void doesNotContain(String textToSearch, String substring) {
        doesNotContain(textToSearch, substring,
                "[Assertion failed] - this String argument must not contain the substring [" + substring + "]");
    }


    /**
     * Assert that an array has elements; that is, it must not be
     * <code>null</code> and must have at least one element.
     * <pre class="code">Assert.notEmpty(array, "The array must have elements");</pre>
     *
     * @param array   the array to check
     * @param message the exception message to use if the assertion fails
     * @return the non-empty array for immediate use
     * @throws IllegalArgumentException if the object array is <code>null</code> or has no elements
     */
    public static Object[] notEmpty(Object[] array, String message) {
        if (Objects.isEmpty(array)) {
            throw new IllegalArgumentException(message);
        }
        return array;
    }

    /**
     * Assert that an array has elements; that is, it must not be
     * <code>null</code> and must have at least one element.
     * <pre class="code">Assert.notEmpty(array);</pre>
     *
     * @param array the array to check
     * @throws IllegalArgumentException if the object array is <code>null</code> or has no elements
     */
    public static void notEmpty(Object[] array) {
        notEmpty(array, "[Assertion failed] - this array must not be empty: it must contain at least 1 element");
    }

    /**
     * Assert that the specified byte array is not null and has at least one byte element.
     *
     * @param array the byte array to check
     * @param msg   the exception message to use if the assertion fails
     * @return the byte array if the assertion passes
     * @throws IllegalArgumentException if the byte array is null or empty
     * @since JJWT_RELEASE_VERSION
     */
    public static byte[] notEmpty(byte[] array, String msg) {
        if (Objects.isEmpty(array)) {
            throw new IllegalArgumentException(msg);
        }
        return array;
    }

    /**
     * Assert that the specified character array is not null and has at least one byte element.
     *
     * @param chars the character array to check
     * @param msg   the exception message to use if the assertion fails
     * @return the character array if the assertion passes
     * @throws IllegalArgumentException if the character array is null or empty
     * @since JJWT_RELEASE_VERSION
     */
    public static char[] notEmpty(char[] chars, String msg) {
        if (Objects.isEmpty(chars)) {
            throw new IllegalArgumentException(msg);
        }
        return chars;
    }

    /**
     * Assert that an array has no null elements.
     * Note: Does not complain if the array is empty!
     * <pre class="code">Assert.noNullElements(array, "The array must have non-null elements");</pre>
     *
     * @param array   the array to check
     * @param message the exception message to use if the assertion fails
     * @throws IllegalArgumentException if the object array contains a <code>null</code> element
     */
    public static void noNullElements(Object[] array, String message) {
        if (array != null) {
            for (int i = 0; i < array.length; i++) {
                if (array[i] == null) {
                    throw new IllegalArgumentException(message);
                }
            }
        }
    }

    /**
     * Assert that an array has no null elements.
     * Note: Does not complain if the array is empty!
     * <pre class="code">Assert.noNullElements(array);</pre>
     *
     * @param array the array to check
     * @throws IllegalArgumentException if the object array contains a <code>null</code> element
     */
    public static void noNullElements(Object[] array) {
        noNullElements(array, "[Assertion failed] - this array must not contain any null elements");
    }

    /**
     * Assert that a collection has elements; that is, it must not be
     * <code>null</code> and must have at least one element.
     * <pre class="code">Assert.notEmpty(collection, "Collection must have elements");</pre>
     *
     * @param collection the collection to check
     * @param <T>        the type of collection
     * @param message    the exception message to use if the assertion fails
     * @return the non-null, non-empty collection
     * @throws IllegalArgumentException if the collection is <code>null</code> or has no elements
     */
    public static <T extends Collection<?>> T notEmpty(T collection, String message) {
        if (Collections.isEmpty(collection)) {
            throw new IllegalArgumentException(message);
        }
        return collection;
    }

    /**
     * Assert that a collection has elements; that is, it must not be
     * <code>null</code> and must have at least one element.
     * <pre class="code">Assert.notEmpty(collection, "Collection must have elements");</pre>
     *
     * @param collection the collection to check
     * @throws IllegalArgumentException if the collection is <code>null</code> or has no elements
     */
    public static void notEmpty(Collection<?> collection) {
        notEmpty(collection,
                "[Assertion failed] - this collection must not be empty: it must contain at least 1 element");
    }

    /**
     * Assert that a Map has entries; that is, it must not be <code>null</code>
     * and must have at least one entry.
     * <pre class="code">Assert.notEmpty(map, "Map must have entries");</pre>
     *
     * @param map     the map to check
     * @param <T>     the type of Map to check
     * @param message the exception message to use if the assertion fails
     * @return the non-null, non-empty map
     * @throws IllegalArgumentException if the map is <code>null</code> or has no entries
     */
    public static <T extends Map<?, ?>> T notEmpty(T map, String message) {
        if (Collections.isEmpty(map)) {
            throw new IllegalArgumentException(message);
        }
        return map;
    }

    /**
     * Assert that a Map has entries; that is, it must not be <code>null</code>
     * and must have at least one entry.
     * <pre class="code">Assert.notEmpty(map);</pre>
     *
     * @param map the map to check
     * @throws IllegalArgumentException if the map is <code>null</code> or has no entries
     */
    public static void notEmpty(Map map) {
        notEmpty(map, "[Assertion failed] - this map must not be empty; it must contain at least one entry");
    }


    /**
     * Assert that the provided object is an instance of the provided class.
     * <pre class="code">Assert.instanceOf(Foo.class, foo);</pre>
     *
     * @param <T>   the type of instance expected
     * @param clazz the required class
     * @param obj   the object to check
     * @return the expected instance of type {@code T}
     * @throws IllegalArgumentException if the object is not an instance of clazz
     * @see Class#isInstance
     */
    public static <T> T isInstanceOf(Class<T> clazz, Object obj) {
        return isInstanceOf(clazz, obj, "");
    }

    /**
     * Assert that the provided object is an instance of the provided class.
     * <pre class="code">Assert.instanceOf(Foo.class, foo);</pre>
     *
     * @param type    the type to check against
     * @param <T>     the object's expected type
     * @param obj     the object to check
     * @param message a message which will be prepended to the message produced by
     *                the function itself, and which may be used to provide context. It should
     *                normally end in a ": " or ". " so that the function generate message looks
     *                ok when prepended to it.
     * @return the non-null object IFF it is an instance of the specified {@code type}.
     * @throws IllegalArgumentException if the object is not an instance of clazz
     * @see Class#isInstance
     */
    public static <T> T isInstanceOf(Class<T> type, Object obj, String message) {
        notNull(type, "Type to check against must not be null");
        if (!type.isInstance(obj)) {
            throw new IllegalArgumentException(message +
                    "Object of class [" + (obj != null ? obj.getClass().getName() : "null") +
                    "] must be an instance of " + type);
        }
        return type.cast(obj);
    }

    /**
     * Assert that <code>superType.isAssignableFrom(subType)</code> is <code>true</code>.
     * <pre class="code">Assert.isAssignable(Number.class, myClass);</pre>
     *
     * @param superType the super type to check
     * @param subType   the sub type to check
     * @throws IllegalArgumentException if the classes are not assignable
     */
    public static void isAssignable(Class superType, Class subType) {
        isAssignable(superType, subType, "");
    }

    /**
     * Assert that <code>superType.isAssignableFrom(subType)</code> is <code>true</code>.
     * <pre class="code">Assert.isAssignable(Number.class, myClass);</pre>
     *
     * @param superType the super type to check against
     * @param subType   the sub type to check
     * @param message   a message which will be prepended to the message produced by
     *                  the function itself, and which may be used to provide context. It should
     *                  normally end in a ": " or ". " so that the function generate message looks
     *                  ok when prepended to it.
     * @throws IllegalArgumentException if the classes are not assignable
     */
    public static void isAssignable(Class superType, Class subType, String message) {
        notNull(superType, "Type to check against must not be null");
        if (subType == null || !superType.isAssignableFrom(subType)) {
            throw new IllegalArgumentException(message + subType + " is not assignable to " + superType);
        }
    }

    /**
     * Asserts that a specified {@code value} is equal to the given {@code requirement}, throwing
     * an {@link IllegalArgumentException} with the given message if not.
     *
     * @param <T>         the type of argument
     * @param value       the value to check
     * @param requirement the requirement that {@code value} must be greater than
     * @param msg         the message to use for the {@code IllegalArgumentException} if thrown.
     * @return {@code value} if greater than the specified {@code requirement}.
     * @since JJWT_RELEASE_VERSION
     */
    public static <T extends Comparable<T>> T eq(T value, T requirement, String msg) {
        if (compareTo(value, requirement) != 0) {
            throw new IllegalArgumentException(msg);
        }
        return value;
    }

    private static <T extends Comparable<T>> int compareTo(T value, T requirement) {
        notNull(value, "value cannot be null.");
        notNull(requirement, "requirement cannot be null.");
        return value.compareTo(requirement);
    }

    /**
     * Asserts that a specified {@code value} is greater than the given {@code requirement}, throwing
     * an {@link IllegalArgumentException} with the given message if not.
     *
     * @param <T>         the type of value to check and return if the requirement is met
     * @param value       the value to check
     * @param requirement the requirement that {@code value} must be greater than
     * @param msg         the message to use for the {@code IllegalArgumentException} if thrown.
     * @return {@code value} if greater than the specified {@code requirement}.
     * @since JJWT_RELEASE_VERSION
     */
    public static <T extends Comparable<T>> T gt(T value, T requirement, String msg) {
        if (!(compareTo(value, requirement) > 0)) {
            throw new IllegalArgumentException(msg);
        }
        return value;
    }

    /**
     * Asserts that a specified {@code value} is less than or equal to the given {@code requirement}, throwing
     * an {@link IllegalArgumentException} with the given message if not.
     *
     * @param <T>         the type of value to check and return if the requirement is met
     * @param value       the value to check
     * @param requirement the requirement that {@code value} must be greater than
     * @param msg         the message to use for the {@code IllegalArgumentException} if thrown.
     * @return {@code value} if greater than the specified {@code requirement}.
     * @since JJWT_RELEASE_VERSION
     */
    public static <T extends Comparable<T>> T lte(T value, T requirement, String msg) {
        if (compareTo(value, requirement) > 0) {
            throw new IllegalArgumentException(msg);
        }
        return value;
    }


    /**
     * Assert a boolean expression, throwing <code>IllegalStateException</code>
     * if the test result is <code>false</code>. Call isTrue if you wish to
     * throw IllegalArgumentException on an assertion failure.
     * <pre class="code">Assert.state(id == null, "The id property must not already be initialized");</pre>
     *
     * @param expression a boolean expression
     * @param message    the exception message to use if the assertion fails
     * @throws IllegalStateException if expression is <code>false</code>
     */
    public static void state(boolean expression, String message) {
        if (!expression) {
            throw new IllegalStateException(message);
        }
    }

    /**
     * Assert a boolean expression, throwing {@link IllegalStateException}
     * if the test result is <code>false</code>.
     * <p>Call {@link #isTrue(boolean)} if you wish to
     * throw {@link IllegalArgumentException} on an assertion failure.
     * <pre class="code">Assert.state(id == null);</pre>
     *
     * @param expression a boolean expression
     * @throws IllegalStateException if the supplied expression is <code>false</code>
     */
    public static void state(boolean expression) {
        state(expression, "[Assertion failed] - this state invariant must be true");
    }

    /**
     * Asserts that the specified {@code value} is not null, otherwise throws an
     * {@link IllegalStateException} with the specified {@code msg}.  Intended to be used with
     * code invariants (as opposed to method arguments, like {@link #notNull(Object)}).
     *
     * @param value value to assert is not null
     * @param msg   exception message to use if {@code value} is null
     * @param <T>   value type
     * @return the non-null value
     * @throws IllegalStateException with the specified {@code msg} if {@code value} is null.
     * @since JJWT_RELEASE_VERSION
     */
    public static <T> T stateNotNull(T value, String msg) throws IllegalStateException {
        if (value == null) {
            throw new IllegalStateException(msg);
        }
        return value;
    }

}
