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

import io.jsonwebtoken.lang.Classes;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class OptionalMethodInvoker<T, R> extends ReflectionFunction<T, R> {

    private final Class<?> CLASS;
    private final Method METHOD;

    private final Class<?>[] PARAM_TYPES;
    private final boolean STATIC;

    public OptionalMethodInvoker(String fqcn, String methodName) {
        this(fqcn, methodName, null, false);
    }

    public OptionalMethodInvoker(String fqcn, String methodName, Class<?> paramType, boolean isStatic) {
        Class<?> clazz = null;
        Method method = null;
        Class<?>[] paramTypes = paramType != null ? new Class<?>[]{paramType} : null;
        try {
            clazz = Classes.forName(fqcn);
            method = clazz.getMethod(methodName, paramTypes);
        } catch (Throwable ignored) {
        }
        this.CLASS = clazz;
        this.METHOD = method;
        this.PARAM_TYPES = paramTypes;
        this.STATIC = isStatic;
    }

    @Override
    protected boolean supports(T input) {
        Class<?> clazz = null;
        if (CLASS != null && METHOD != null) {
            clazz = STATIC && PARAM_TYPES != null ? PARAM_TYPES[0] : CLASS;
        }
        return clazz != null && clazz.isInstance(input);
    }

    @SuppressWarnings("unchecked")
    @Override
    protected R invoke(T input) throws InvocationTargetException, IllegalAccessException {
        return (STATIC) ? (R) METHOD.invoke(null, input) : (R) METHOD.invoke(input);
    }
}
