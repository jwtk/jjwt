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
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public class StringRegistry<V> extends DefaultRegistry<String, V> {

    private final Function<String, String> CASE_FN;

    private final Map<String, V> CI_VALUES;

    public StringRegistry(String name, String keyName, Collection<V> values, Function<V, String> keyFn, boolean caseSensitive) {
        this(name, keyName, values, keyFn, caseSensitive ? Functions.<String>identity() : CaseInsensitiveFunction.ENGLISH);
    }

    public StringRegistry(String name, String keyName, Collection<V> values, Function<V, String> keyFn, Function<String, String> caseFn) {
        super(name, keyName, values, keyFn);
        this.CASE_FN = Assert.notNull(caseFn, "Case function cannot be null.");
        Map<String, V> m = new LinkedHashMap<>(values().size());
        for (V value : values) {
            String key = keyFn.apply(value);
            key = this.CASE_FN.apply(key);
            m.put(key, value);
        }
        this.CI_VALUES = Collections.immutable(m);
    }

    @Override
    public V get(Object key) {
        String id = (String) key; // could throw ClassCastException as allowed per Map 'get' contract
        Assert.hasText(id, "id argument cannot be null or empty.");
        V instance = super.get(id); //try standard ID lookup first.  This will satisfy 99% of invocations
        if (instance == null) { // fall back to case-insensitive ID lookup:
            id = CASE_FN.apply(id);
            instance = CI_VALUES.get(id);
        }
        return instance;
    }

    private static final class CaseInsensitiveFunction implements Function<String, String> {

        private static final CaseInsensitiveFunction ENGLISH = new CaseInsensitiveFunction(Locale.ENGLISH);

        private final Locale LOCALE;

        private CaseInsensitiveFunction(Locale locale) {
            this.LOCALE = Assert.notNull(locale, "Case insensitive Locale argument cannot be null.");
        }

        @Override
        public String apply(String s) {
            s = Assert.notNull(Strings.clean(s), "String identifier cannot be null or empty.");
            return s.toUpperCase(LOCALE);
        }
    }
}
