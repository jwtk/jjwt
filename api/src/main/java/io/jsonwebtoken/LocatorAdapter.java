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
package io.jsonwebtoken;

import io.jsonwebtoken.lang.Assert;

/**
 * Adapter pattern implementation for the {@link Locator} interface.  Subclasses can override any of the
 * {@link #locate(UnprotectedHeader)}, {@link #locate(ProtectedHeader)}, {@link #locate(JwsHeader)}, or
 * {@link #locate(JweHeader)} methods for type-specific logic if desired when the encountered header is an
 * unprotected JWT, or an integrity-protected JWT (either a JWS or JWE).
 *
 * @since JJWT_RELEASE_VERSION
 */
public abstract class LocatorAdapter<T> implements Locator<T> {

    /**
     * Constructs a new instance, where all default method implementations return {@code null}.
     */
    public LocatorAdapter() {
    }

    /**
     * Inspects the specified header, and delegates to the {@link #locate(UnprotectedHeader)} method if the header
     * is an {@link UnprotectedHeader} or the {@link #locate(ProtectedHeader)} method if the header is either a
     * {@link JwsHeader} or {@link JweHeader}.
     *
     * @param header the JWT header to inspect; may be an instance of {@link UnprotectedHeader}, {@link JwsHeader} or
     *               {@link JweHeader} depending on if the respective JWT is an unprotected JWT, JWS or JWE.
     * @return an object referenced in the specified header, or {@code null} if the referenced object cannot be found
     * or does not exist.
     */
    @Override
    public final T locate(Header header) {
        Assert.notNull(header, "Header cannot be null.");
        if (header instanceof ProtectedHeader) {
            ProtectedHeader protectedHeader = (ProtectedHeader) header;
            return locate(protectedHeader);
        } else {
            Assert.isInstanceOf(UnprotectedHeader.class, header, "Unrecognized Header type.");
            return locate((UnprotectedHeader) header);
        }
    }

    /**
     * Returns an object referenced in the specified {@link ProtectedHeader}, or {@code null} if the referenced
     * object cannot be found or does not exist.  This is a convenience method that delegates to
     * {@link #locate(JwsHeader)} if the {@code header} is a {@link JwsHeader} or {@link #locate(JweHeader)} if the
     * {@code header} is a {@link JweHeader}.
     *
     * @param header the protected header of an encountered JWS or JWE.
     * @return an object referenced in the specified {@link ProtectedHeader}, or {@code null} if the referenced
     * object cannot be found or does not exist.
     */
    protected T locate(ProtectedHeader header) {
        if (header instanceof JwsHeader) {
            return locate((JwsHeader) header);
        } else {
            Assert.isInstanceOf(JweHeader.class, header, "Unrecognized ProtectedHeader type.");
            return locate((JweHeader) header);
        }
    }

    /**
     * Returns an object referenced in the specified JWE header, or {@code null} if the referenced
     * object cannot be found or does not exist.  Default implementation simply returns {@code null}.
     *
     * @param header the header of an encountered JWE.
     * @return an object referenced in the specified JWE header, or {@code null} if the referenced
     * object cannot be found or does not exist.
     */
    protected T locate(JweHeader header) {
        return null;
    }

    /**
     * Returns an object referenced in the specified JWS header, or {@code null} if the referenced
     * object cannot be found or does not exist. Default implementation simply returns {@code null}.
     *
     * @param header the header of an encountered JWS.
     * @return an object referenced in the specified JWS header, or {@code null} if the referenced
     * object cannot be found or does not exist.
     */
    protected T locate(JwsHeader header) {
        return null;
    }

    /**
     * Returns an object referenced in the specified Unprotected JWT header, or {@code null} if the referenced
     * object cannot be found or does not exist. Default implementation simply returns {@code null}.
     *
     * @param header the header of an encountered JWE.
     * @return an object referenced in the specified Unprotected JWT header, or {@code null} if the referenced
     * object cannot be found or does not exist.
     */
    protected T locate(UnprotectedHeader header) {
        return null;
    }
}
