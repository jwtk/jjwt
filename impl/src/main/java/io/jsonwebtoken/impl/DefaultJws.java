/*
 * Copyright (C) 2014 jsonwebtoken.io
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

import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.io.Decoders;

public class DefaultJws<P> extends DefaultProtectedJwt<JwsHeader, P> implements Jws<P> {

    private static final String DIGEST_NAME = "signature";

    private final String signature;

    public DefaultJws(JwsHeader header, P payload, String signature) {
        super(header, payload, Decoders.BASE64URL.decode(signature), DIGEST_NAME);
        this.signature = signature;
    }

    @Override
    public String getSignature() {
        return this.signature;
    }

}
