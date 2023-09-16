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
 * Type-safe interface that reflects the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder pattern</a>.
 *
 * @param <T> The type of object that will be created when {@link #build()} is invoked.
 * @since JJWT_RELEASE_VERSION
 */
public interface Builder<T> {

    /**
     * Creates and returns a new instance of type {@code T}.
     *
     * @return a new instance of type {@code T}.
     */
    T build();
}
