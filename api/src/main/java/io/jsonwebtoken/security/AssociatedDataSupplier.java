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

/**
 * Provides any &quot;associated data&quot; that must be integrity protected (but not encrypted) when performing
 * <a href="https://en.wikipedia.org/wiki/Authenticated_encryption">AEAD encryption or decryption</a>.
 *
 * @see #getAssociatedData()
 * @since JJWT_RELEASE_VERSION
 */
public interface AssociatedDataSupplier {

    /**
     * Returns any data that must be integrity protected (but not encrypted) when performing
     * <a href="https://en.wikipedia.org/wiki/Authenticated_encryption">AEAD encryption or decryption</a>, or
     * {@code null} if no additional data must be integrity protected.
     *
     * @return any data that must be integrity protected (but not encrypted) when performing
     * <a href="https://en.wikipedia.org/wiki/Authenticated_encryption">AEAD encryption or decryption</a>, or
     * {@code null} if no additional data must be integrity protected.
     */
    byte[] getAssociatedData();
}
