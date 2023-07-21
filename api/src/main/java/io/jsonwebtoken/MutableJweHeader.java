/*
 * Copyright (C) 2023 jsonwebtoken.io
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
package io.jsonwebtoken;

/**
 * Read and write operations for standard header parameters (JWE header parameters are a superset of all JWE, Protected
 * and Unprotected Header parameters).  All write methods support method chaining for continuous configuration.
 *
 * @param <T>
 * @since JJWT_RELEASE_VERSION
 */
public interface MutableJweHeader<T extends MutableJweHeader<T>> extends JweHeaderAccessor, JweHeaderMutator<T> {
}
