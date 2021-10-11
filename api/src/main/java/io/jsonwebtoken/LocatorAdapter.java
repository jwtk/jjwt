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
 * @since JJWT_RELEASE_VERSION
 */
public abstract class LocatorAdapter<H extends Header<H>, R> implements Locator<H, R> {

    @Override
    public final R locate(H header) {
        Assert.notNull(header, "Header cannot be null.");
        if (header instanceof JwsHeader) {
            return locate((JwsHeader) header);
        } else if (header instanceof JweHeader) {
            return locate((JweHeader) header);
        } else {
            return doLocate(header);
        }
    }

    protected R locate(JweHeader header) {
        return null;
    }

    protected R locate(JwsHeader header) {
        return null;
    }

    protected R doLocate(Header<?> header) {
        return null;
    }
}
