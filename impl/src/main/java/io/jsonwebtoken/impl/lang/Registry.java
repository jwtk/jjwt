package io.jsonwebtoken.impl.lang;

import java.util.Collection;

public interface Registry<I, T> extends Function<I, T> {

    Collection<T> values();
}
