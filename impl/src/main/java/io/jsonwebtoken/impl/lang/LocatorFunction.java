package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.lang.Assert;

public class LocatorFunction<T> implements Function<Header<?>, T> {

    private final Locator<T> locator;

    public LocatorFunction(Locator<T> locator) {
        this.locator = Assert.notNull(locator, "Locator instance cannot be null.");
    }

    @Override
    public T apply(Header<?> h) {
        return this.locator.locate(h);
    }
}
