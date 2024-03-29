/*
 * Copyright (C) 2021 jsonwebtoken.io
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

import java.security.Key;

/**
 * A request to a cryptographic algorithm requiring a {@link Key}.
 *
 * @param <T> the type of payload in the request
 * @param <K> they type of key used by the algorithm during the request
 * @since 0.12.0
 */
public interface SecureRequest<T, K extends Key> extends Request<T>, KeySupplier<K> {
}
