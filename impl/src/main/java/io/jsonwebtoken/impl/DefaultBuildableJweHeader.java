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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.MutableJweHeader;
import io.jsonwebtoken.security.X509Builder;

/**
 * @param <T> return type for method chaining
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultBuildableJweHeader<T extends MutableJweHeader<T> & X509Builder<T>>
        extends DefaultMutableJweHeader<T> implements X509Builder<T> {

    public DefaultBuildableJweHeader() {
        super();
    }

    public DefaultBuildableJweHeader(DefaultMutableJweHeader<?> src) {
        super(src);
    }

    @Override
    public T withX509Sha1Thumbprint(boolean enable) {
        this.x509.withX509Sha1Thumbprint(enable);
        return self();
    }

    @Override
    public T withX509Sha256Thumbprint(boolean enable) {
        this.x509.withX509Sha256Thumbprint(enable);
        return self();
    }
}
