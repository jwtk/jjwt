/*
 * Copyright (C) 2014 jsonwebtoken.io
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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.Clock;

import java.time.Instant;
import java.util.Date;

/**
 * A {@code Clock} implementation that is constructed with a seed timestamp and always reports that same
 * timestamp.
 *
 * @since 0.7.0
 */
public class FixedClock implements Clock {

    private final Instant instant;

    /**
     * Creates a new fixed clock using {@link Instant#now()} as the seed timestamp.  All calls to
     * {@link #instant instant()} will always return this seed Instant.
     */
    public FixedClock() {
        this(Instant.now());
    }

    /**
     * Creates a new fixed clock using the specified seed timestamp.  All calls to
     * {@link #instant instant()} will always return this seed Instant.
     *
     * @param instant the specified Instant to always return from all calls to {@link #instant instant()}.
     * @since 0.14.0
     */
    public FixedClock(Instant instant) {
        this.instant = instant;
    }

    /**
     * Creates a new fixed clock using the specified seed timestamp.  All calls to
     * {@link #instant instant()} will always return this seed timestamp.
     *
     * @param now the specified Date to always return from all calls to {@link #now now()}.
     * @deprecated since 0.14.0 in favor of {@link #FixedClock(Instant)}. This constructor will be removed before
     * the JJWT 1.0 release.
     */
    @Deprecated
    public FixedClock(Date now) {
        this(now != null ? now.toInstant() : null);
    }

    /**
     * Creates a new fixed clock using the specified seed timestamp.  All calls to
     * {@link #instant instant()} will always return this seed timestamp.
     *
     * @param timeInMillis the specified timestamp in milliseconds to always return from all calls to
     *                     {@link #instant instant()}.
     */
    public FixedClock(long timeInMillis) {
        this(Instant.ofEpochMilli(timeInMillis));
    }

    @Override
    public Instant instant() {
        return this.instant;
    }

    /**
     * Returns the seed timestamp as a new {@link Date} instance.
     *
     * @return the seed timestamp as a new {@link Date} instance, or {@code null} if the seed is {@code null}.
     * @deprecated since 0.14.0 in favor of {@link #instant()}. This method will be removed before the
     * JJWT 1.0 release.
     */
    @SuppressWarnings("deprecation")
    @Deprecated
    @Override
    public Date now() {
        return this.instant != null ? Date.from(this.instant) : null;
    }
}
