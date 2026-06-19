/*
 * Copyright © 2026 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.DigestRequest;

import java.io.InputStream;
import java.security.Provider;
import java.security.SecureRandom;

@SuppressWarnings("unused")
public class DefaultDigestRequest extends DefaultRequest<InputStream> implements DigestRequest {

    DefaultDigestRequest(InputStream payload, Provider provider, SecureRandom secureRandom) {
        super(payload, provider, secureRandom);
    }

    @SuppressWarnings("unused") // instantiated via reflection in io.jsonwebtoken.security.Suppliers
    public static class Builder extends AbstractPayloadParams<InputStream, DigestRequest.Builder>
            implements DigestRequest.Builder {

        @Override
        public DigestRequest build() {
            return new DefaultDigestRequest(this.payload, this.provider, this.random);
        }

        public static class Supplier implements java.util.function.Supplier<DigestRequest.Builder> {
            @Override
            public DigestRequest.Builder get() {
                return new Builder();
            }
        }
    }
}
