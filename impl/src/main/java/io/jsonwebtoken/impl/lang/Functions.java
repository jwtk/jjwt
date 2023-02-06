/*
 * Copyright © 2022 jsonwebtoken.io
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

public final class Functions {

    private static final Function<?, ?> NULL = new Function<Object, Object>() {
        @Override
        public Object apply(Object o) {
            return null;
        }
    };

    private Functions() {
    }

    @SuppressWarnings("unchecked")
    public static <T, R> Function<T, R> NULL() {
        return (Function<T, R>) NULL;
    }

    /**
     * Wraps the specified function to ensure that if any exception occurs, it is of the specified type and/or with
     * the specified message.  If no exception occurs, the function's return value is returned as expected.
     *
     * <p>If {@code fn} throws an exception, its type is checked.  If it is already of type {@code exClass}, that
     * exception is immediately thrown.  If it is not the expected exception type, a message is created with the
     * specified {@code msg} template, and a new exception of the specified type is thrown with the formatted message,
     * using the original exception as its cause.</p>
     *
     * @param fn      the function to execute
     * @param exClass the exception type expected, if any
     * @param msg     the formatted message to use if throwing a new exception, used as the first argument to {@link String#format(String, Object...) String.format}.
     * @param <T>     the function argument type
     * @param <R>     the function's return type
     * @param <E>     type of exception to ensure
     * @return the wrapping function instance.
     */
    public static <T, R, E extends RuntimeException> Function<T, R> wrapFmt(CheckedFunction<T, R> fn, Class<E> exClass, String msg) {
        return new PropagatingExceptionFunction<>(fn, exClass, new FormattedStringFunction<T>(msg));
    }

    public static <T, R, E extends RuntimeException> Function<T, R> wrap(Function<T, R> fn, Class<E> exClass, String fmt, Object... args) {
        return new PropagatingExceptionFunction<>(new DelegatingCheckedFunction<>(fn), exClass, new FormattedStringSupplier(fmt, args));
    }

    /**
     * Returns a composed function that first applies this function to
     * its input, and then applies the {@code after} function to the result.
     * If evaluation of either function throws an exception, it is relayed to
     * the caller of the composed function.
     *
     * @param <V>   the type of output of the {@code after} function, and of the
     *              composed function
     * @param after the function to apply after this function is applied
     * @return a composed function that first applies this function and then
     * applies the {@code after} function
     * @throws IllegalArgumentException if either {@code before} or {@code after} are null.
     */
    public static <T, V, R> Function<T, R> andThen(final Function<T, ? extends V> before, final Function<V, R> after) {
        Assert.notNull(before, "Before function cannot be null.");
        Assert.notNull(after, "After function cannot be null.");
        return new Function<T, R>() {
            @Override
            public R apply(T t) {
                V result = before.apply(t);
                return after.apply(result);
            }
        };
    }

    /**
     * Returns a composed function that invokes the specified functions in iteration order, and returns the first
     * non-null result.  Once a non-null result is discovered, no further functions will be invoked, 'short-circuiting'
     * any remaining functions. If evaluation of any function throws an exception, it is relayed to the caller of the
     * composed function.
     *
     * @param <R> the type of output of the functions, and of the composed function
     * @param fns the functions to iterate
     * @return a composed function that invokes the specified functions in iteration order, returning the first non-null
     * result.
     * @throws NullPointerException if after is null
     */
    @SafeVarargs
    public static <T, R> Function<T, R> firstResult(final Function<T, R>... fns) {
        Assert.notEmpty(fns, "Function list cannot be null or empty.");
        return new Function<T, R>() {
            @Override
            public R apply(T t) {
                for (Function<T, R> fn : fns) {
                    Assert.notNull(fn, "Function cannot be null.");
                    R result = fn.apply(t);
                    if (result != null) {
                        return result;
                    }
                }
                return null;
            }
        };
    }
}
