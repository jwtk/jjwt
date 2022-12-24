package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;

public class IdRegistry<T extends Identifiable> extends StringRegistry<T> {

    private static final Function<Identifiable, String> FN = new Function<Identifiable, String>() {
        @Override
        public String apply(Identifiable identifiable) {
            Assert.notNull(identifiable, "Identifiable argument cannot be null.");
            return Assert.notNull(Strings.clean(identifiable.getId()), "Identifier cannot be null or empty.");
        }
    };

    @SuppressWarnings("unchecked")
    public IdRegistry(Collection<T> instances) {
        super(Assert.notEmpty(instances, "Collection of Identifiable instances may not be null or empty."),
                (Function<T, String>) FN);
    }
}
