/*
 * Copyright (C) 2022 jsonwebtoken.io
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

import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkBuilder;
import io.jsonwebtoken.security.JwkParser;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.KeyOperationPolicy;
import io.jsonwebtoken.security.MalformedKeyException;

import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.util.Map;

public class DefaultJwkParser implements JwkParser {

    private final Provider provider;

    private final Deserializer<Map<String, ?>> deserializer;

    private final KeyOperationPolicy opsPolicy;

    public DefaultJwkParser(Provider provider, Deserializer<Map<String, ?>> deserializer, KeyOperationPolicy policy) {
        this.provider = provider;
        this.deserializer = Assert.notNull(deserializer, "Deserializer cannot be null.");
        Assert.notNull(policy, "KeyOperationPolicy cannot be null.");
        Assert.notEmpty(policy.getOperations(), "KeyOperationPolicy's operations cannot be null or empty.");
        this.opsPolicy = policy;
    }

    // visible for testing
    protected Map<String, ?> deserialize(String json) {
        byte[] data = json.getBytes(StandardCharsets.UTF_8);
        return this.deserializer.deserialize(data);
    }

    @Override
    public Jwk<?> parse(String json) throws KeyException {
        Assert.hasText(json, "JSON string argument cannot be null or empty.");
        Map<String, ?> data;
        try {
            data = deserialize(json);
        } catch (Exception e) {
            String msg = "Unable to deserialize JSON string argument: " + e.getMessage();
            throw new MalformedKeyException(msg);
        }

        JwkBuilder<?, ?, ?> builder = Jwks.builder().operationPolicy(this.opsPolicy);

        if (this.provider != null) {
            builder.provider(this.provider);
        }

        return builder.add(data).build();
    }
}
