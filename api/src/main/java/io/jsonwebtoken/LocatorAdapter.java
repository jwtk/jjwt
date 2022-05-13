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
 * {@link #locate(Header)}, {@link #locate(JwsHeader)}, or {@link #locate(JwsHeader)} methods for type-specific logic if
 * desired when the encountered header is an unprotected JWT, JWS or JWE respectively.
 *
 * @since JJWT_RELEASE_VERSION
 */
public class LocatorAdapter<T> implements Locator<T> {

    @Override
    public final T locate(Header<?> header) {
        Assert.notNull(header, "Header cannot be null.");
        if (header instanceof JwsHeader) {
            JwsHeader jwsHeader = (JwsHeader) header;
            return locate(jwsHeader);
        } else if (header instanceof JweHeader) {
            JweHeader jweHeader = (JweHeader) header;
            return locate(jweHeader);
        } else {
            return doLocate(header);
        }
    }

    protected T locate(JweHeader header) {
        return null;
    }

    protected T locate(JwsHeader header) {
        return null;
    }

    protected T doLocate(Header<?> header) {
        return null;
    }
}
