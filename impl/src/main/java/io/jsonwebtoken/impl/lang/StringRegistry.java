package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public class StringRegistry<V> extends DefaultRegistry<String, V> {

    private final Function<String, String> CI_FN;

    private final Map<String, V> CI_VALUES;

    public StringRegistry(Collection<V> values, Function<V, String> keyFn) {
        this(values, keyFn, Locale.ENGLISH);
    }

    public StringRegistry(Collection<V> values, Function<V, String> keyFn, final Locale caseInsensitiveLocale) {
        super(values, keyFn);
        this.CI_FN = new CaseInsensitiveFunction(caseInsensitiveLocale);
        Map<String, V> m = new LinkedHashMap<>(values().size());
        for (V value : values) {
            String key = keyFn.apply(value);
            key = this.CI_FN.apply(key);
            m.put(key, value);
        }
        this.CI_VALUES = Collections.immutable(m);
    }

    @Override
    public V apply(String id) {
        Assert.hasText(id, "id argument cannot be null or empty.");
        V instance = super.apply(id); //try standard ID lookup first.  This will satisfy 99% of invocations
        if (instance == null) { // fall back to case-insensitive ID lookup:
            id = CI_FN.apply(id);
            instance = CI_VALUES.get(id);
        }
        return instance;
    }

    private static final class CaseInsensitiveFunction implements Function<String, String> {
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
