/*
 * Copyright © 2023 jsonwebtoken.io
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

import io.jsonwebtoken.impl.io.NamedSerializer;
import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.Jwk;

import java.io.ByteArrayOutputStream;
import java.util.Map;

public final class JwksBridge {

    private JwksBridge() {
    }

    @SuppressWarnings({"unchecked", "unused"}) // used via reflection by io.jsonwebtoken.security.Jwks
    public static String UNSAFE_JSON(Jwk<?> jwk) {
        Serializer<Map<String, ?>> serializer = Services.get(Serializer.class);
        Assert.stateNotNull(serializer, "Serializer lookup failed. Ensure JSON impl .jar is in the runtime classpath.");
        NamedSerializer ser = new NamedSerializer("JWK", serializer);
        ByteArrayOutputStream out = new ByteArrayOutputStream(512);
        ser.serialize(jwk, out);
        return Strings.utf8(out.toByteArray());
    }
}
