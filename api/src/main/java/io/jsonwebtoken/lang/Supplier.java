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
package io.jsonwebtoken.lang;

/**
 * Represents a supplier of results.
 *
 * <p>There is no requirement that a new or distinct result be returned each time the supplier is invoked.</p>
 *
 * <p>This interface is the equivalent of a JDK 8 {@code java.util.function.Supplier}, backported for JJWT's use in
 * JDK 7 environments.</p>
 *
 * @param <T> the type of object returned by this supplier
 * @since JJWT_RELEASE_VERSION
 */
public interface Supplier<T> {

    /**
     * Returns a result.
     *
     * @return a result.
     */
    T get();
}
