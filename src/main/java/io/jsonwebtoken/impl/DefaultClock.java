package io.jsonwebtoken.impl;

import io.jsonwebtoken.Clock;

import java.util.Date;

/**
 * Default {@link Clock} implementation.
 *
 * @since 0.7.0
 */
public class DefaultClock implements Clock {

    /**
     * Default static instance that may be shared.  It is thread-safe.
     */
    public static final Clock INSTANCE = new DefaultClock();

    /**
     * Simply returns <code>new {@link Date}()</code>.
     *
     * @return a new {@link Date} instance.
     */
    @Override
    public Date now() {
        return new Date();
    }
}
