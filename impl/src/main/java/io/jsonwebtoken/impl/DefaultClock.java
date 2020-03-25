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
