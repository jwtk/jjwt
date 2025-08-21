/*
 * Copyright (C) 2022 jsonwebtoken.io
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
package io.jsonwebtoken.security;

/**
 * A wrapper for a value that should be treated as confidential.  Calling {@link Object#toString()} on a
 * {@code ConfidentialValue} instance will return the string literal <code>&lt;redacted&gt;</code>.
 *
 * <p>There is no requirement that a new or distinct result be returned each time the value is invoked.</p>
 *
 * @param <T> the type of object returned by this supplier
 * @since 0.14.0, renamed and moved from io.jsonwebtoken.lang.Supplier introduced in 0.12.0
 */
public interface ConfidentialValue<T> {

    /**
     * Returns a confidential value that should be treated with care and not exposed unnecessarily.
     *
     * @return a confidential value that should be treated with care and not exposed unnecessarily.
     */
    T get();
}
