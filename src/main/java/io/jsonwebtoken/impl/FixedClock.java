package io.jsonwebtoken.impl;

import io.jsonwebtoken.Clock;

import java.util.Date;

public class FixedClock implements Clock {
    private final Date now;

    public FixedClock() {
        this(new Date());
    }

    public FixedClock(Date now) {
        this.now = now;
    }

    @Override
    public Date now() {
        return this.now;
    }
}
