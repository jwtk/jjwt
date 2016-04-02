package io.jsonwebtoken.impl;

import io.jsonwebtoken.Clock;

import java.util.Date;

/**
 * A {@code Clock} implementation that is constructed with a seed timestamp and always reports that same
 * timestamp.
 *
 * @since 0.7.0
 */
public class FixedClock implements Clock {

    private final Date now;

    /**
     * Creates a new fixed clock using <code>new {@link Date Date}()</code> as the seed timestamp.  All calls to
     * {@link #now now()} will always return this seed Date.
     */
    public FixedClock() {
        this(new Date());
    }

    /**
     * Creates a new fixed clock using the specified seed timestamp.  All calls to
     * {@link #now now()} will always return this seed Date.
     *
     * @param now the specified Date to always return from all calls to {@link #now now()}.
     */
    public FixedClock(Date now) {
        this.now = now;
    }

    @Override
    public Date now() {
        return this.now;
    }
}
