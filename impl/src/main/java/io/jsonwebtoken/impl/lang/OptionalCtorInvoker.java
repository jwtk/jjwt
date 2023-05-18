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

import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;

public class OptionalCtorInvoker<T> extends ReflectionFunction<Object, T> {

    private final Constructor<T> CTOR;

    public OptionalCtorInvoker(String fqcn, Object... ctorArgTypesOrFqcns) {
        Assert.hasText(fqcn, "fqcn cannot be null.");
        Constructor<T> ctor = null;
        try {
            Class<T> clazz = Classes.forName(fqcn);
            Class<?>[] ctorArgTypes = null;
            if (Arrays.length(ctorArgTypesOrFqcns) > 0) {
                ctorArgTypes = new Class<?>[ctorArgTypesOrFqcns.length];
                List<Class<?>> l = new ArrayList<>(ctorArgTypesOrFqcns.length);
                for (Object ctorArgTypeOrFqcn : ctorArgTypesOrFqcns) {
                    Class<?> ctorArgClass;
                    if (ctorArgTypeOrFqcn instanceof Class<?>) {
                        ctorArgClass = (Class<?>) ctorArgTypeOrFqcn;
                    } else {
                        String typeFqcn = Assert.isInstanceOf(String.class, ctorArgTypeOrFqcn, "ctorArgTypesOrFcqns array must contain Class or String instances.");
                        ctorArgClass = Classes.forName(typeFqcn);
                    }
                    l.add(ctorArgClass);
                }
                ctorArgTypes = l.toArray(ctorArgTypes);
            }
            ctor = Classes.getConstructor(clazz, ctorArgTypes);
        } catch (Exception ignored) {
        }
        this.CTOR = ctor;
    }

    @Override
    protected boolean supports(Object input) {
        return CTOR != null;
    }

    @Override
    protected T invoke(Object input) {
        Object[] args = null;
        if (input instanceof Object[]) {
            args = (Object[]) input;
        } else if (input != null) {
            args = new Object[]{input};
        }
        return Classes.instantiate(CTOR, args);
    }
}
