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

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;

public class IdRegistry<T extends Identifiable> extends StringRegistry<T> {

    public static final Function<Identifiable, String> FN = new Function<Identifiable, String>() {
        @Override
        public String apply(Identifiable identifiable) {
            Assert.notNull(identifiable, "Identifiable argument cannot be null.");
            return Assert.notNull(Strings.clean(identifiable.getId()), "Identifier cannot be null or empty.");
        }
    };

    @SuppressWarnings("unchecked")
    public static <T extends Identifiable> Function<T, String> fn() {
        return (Function<T, String>) FN;
    }

    public IdRegistry(String name, Collection<T> instances) {
        this(name, instances, true);
    }

    public IdRegistry(String name, Collection<T> instances, boolean caseSensitive) {
        super(name, "id",
                Assert.notEmpty(instances, "Collection of Identifiable instances may not be null or empty."),
                IdRegistry.<T>fn(),
                caseSensitive);
    }
}
