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

import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Registry;

import java.util.Map;
import java.util.Set;

public class DefaultJwsHeader extends DefaultProtectedHeader implements JwsHeader {

    // https://datatracker.ietf.org/doc/html/rfc7797#section-3 :
    static final Parameter<Boolean> B64 = Parameters.builder(Boolean.class)
            .setId("b64").setName("Base64url-Encode Payload").build();

    static final Registry<String, Parameter<?>> PARAMS = Parameters.registry(DefaultProtectedHeader.PARAMS, B64);

    public DefaultJwsHeader(Map<String, ?> map) {
        super(PARAMS, map);
    }

    @Override
    public String getName() {
        return "JWS header";
    }

    @Override
    public boolean isPayloadEncoded() {
        Set<String> crit = Collections.nullSafe(getCritical());
        Boolean b64 = get(B64);
        return b64 == null || b64 || !crit.contains(B64.getId());
    }
}
