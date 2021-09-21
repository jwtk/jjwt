package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.lang.Assert;

public class LocatorFunction<H extends Header<H>, R> implements Function<H, R> {

    private final Locator<H, R> locator;

    public LocatorFunction(Locator<H, R> locator) {
        this.locator = Assert.notNull(locator, "Locator instance cannot be null.");
    }

    @Override
    public R apply(H h) {
        return this.locator.locate(h);
    }
}
