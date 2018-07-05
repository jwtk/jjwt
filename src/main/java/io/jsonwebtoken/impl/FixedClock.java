package io.jsonwebtoken.impl;

import io.jsonwebtoken.Clock;

import java.time.Instant;

/**
 * A {@code Clock} implementation that is constructed with a seed timestamp and always reports that same
 * timestamp.
 *
 * @since 0.7.0
 */
public class FixedClock implements Clock {

    private final Instant now;

    /**
     * Creates a new fixed clock using <code>new {@link Instant instant}()</code> as the seed timestamp.  All calls to
     * {@link #now now()} will always return this seed Date.
     */
    public FixedClock() {
        this(Instant.now());
    }

    /**
     * Creates a new fixed clock using the specified seed timestamp.  All calls to
     * {@link #now now()} will always return this seed Instant.
     *
     * @param now the specified Instant to always return from all calls to {@link #now now()}.
     */
    public FixedClock(Instant now) {
        this.now = now;
    }

    @Override
    public Instant now() {
        return this.now;
    }
}
