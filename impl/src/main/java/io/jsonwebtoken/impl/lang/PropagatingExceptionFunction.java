/*
 * Copyright (C) 2022 jsonwebtoken.io
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
import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Supplier;

import java.lang.reflect.Constructor;

public class PropagatingExceptionFunction<T, R, E extends RuntimeException> implements Function<T, R> {

    private final CheckedFunction<T, R> function;

    private final Function<T, String> msgFunction;
    private final Class<E> clazz;

    public PropagatingExceptionFunction(Function<T, R> f, Class<E> exceptionClass, String msg) {
        this(new DelegatingCheckedFunction<>(f), exceptionClass, new ConstantFunction<T, String>(msg));
    }

    public PropagatingExceptionFunction(CheckedFunction<T, R> fn, Class<E> exceptionClass, final Supplier<String> msgSupplier) {
        this(fn, exceptionClass, new Function<T, String>() {
            @Override
            public String apply(T t) {
                return msgSupplier.get();
            }
        });
    }

    public PropagatingExceptionFunction(CheckedFunction<T, R> f, Class<E> exceptionClass, Function<T, String> msgFunction) {
        this.clazz = Assert.notNull(exceptionClass, "Exception class cannot be null.");
        this.msgFunction = Assert.notNull(msgFunction, "msgFunction cannot be null.");
        this.function = Assert.notNull(f, "Function cannot be null");
    }

    @SuppressWarnings("unchecked")
    public R apply(T t) {
        try {
            return function.apply(t);
        } catch (Exception e) {
            if (clazz.isAssignableFrom(e.getClass())) {
                throw clazz.cast(e);
            }
            String msg = this.msgFunction.apply(t);
            if (!msg.endsWith(".")) {
                msg += ".";
            }
            msg += " Cause: " + e.getMessage();
            Class<RuntimeException> clazzz = (Class<RuntimeException>) clazz;
            Constructor<RuntimeException> ctor = Classes.getConstructor(clazzz, String.class, Throwable.class);
            throw Classes.instantiate(ctor, msg, e);
        }
    }
}
