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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;
import java.util.LinkedHashSet;

public class IdLocator<H extends Header, R extends Identifiable> implements Locator<R>, Function<H, R> {

    private final Parameter<String> param;
    private final String requiredMsg;
    private final boolean valueRequired;

    private final Registry<String, R> registry;

    public IdLocator(Parameter<String> param, Registry<String, R> registry, Collection<R> extras, String requiredExceptionMessage) {
        this.param = Assert.notNull(param, "Header param cannot be null.");
        this.requiredMsg = Strings.clean(requiredExceptionMessage);
        this.valueRequired = Strings.hasText(this.requiredMsg);
        Assert.notEmpty(registry, "Registry cannot be null or empty.");
        Collection<R> all = new LinkedHashSet<>(Collections.size(registry) + Collections.size(extras));
        all.addAll(registry.values()); // defaults MUST come before extras to allow extras to override if necessary
        all.addAll(extras);

        // The registry requires CaSe-SeNsItIvE keys on purpose - all JWA standard algorithm identifiers
        // (JWS 'alg', JWE 'enc', JWK 'kty', etc) are all case-sensitive per via the following RFC language:
        //
        //     This name is a case-sensitive ASCII string.  Names may not match other registered names in a
        //     case-insensitive manner unless the Designated Experts state that there is a compelling reason to
        //     allow an exception.
        //
        // References:
        // - JWS/JWE alg and JWE enc 'Algorithm Name': https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1.1
        // - JWE zip 'Compression Algorithm Value': https://www.rfc-editor.org/rfc/rfc7518.html#section-7.3.1
        // - JWK '"kty" Parameter Value': https://www.rfc-editor.org/rfc/rfc7518.html#section-7.4.1

        this.registry = new IdRegistry<>(param.getName(), all); // do not use the caseSensitive ctor argument - must be false
    }

    private static String type(Header header) {
        if (header instanceof JweHeader) {
            return "JWE";
        } else if (header instanceof JwsHeader) {
            return "JWS";
        } else {
            return "JWT";
        }
    }

    @Override
    public R locate(Header header) {
        Assert.notNull(header, "Header argument cannot be null.");

        Object val = header.get(this.param.getId());
        String id = val != null ? val.toString() : null;

        if (!Strings.hasText(id)) {
            if (this.valueRequired) {
                throw new MalformedJwtException(requiredMsg);
            }
            return null; // otherwise header value not required, so short circuit
        }

        try {
            return registry.forKey(id);
        } catch (Exception e) {
            String msg = "Unrecognized " + type(header) + " " + this.param + " header value: " + id;
            throw new UnsupportedJwtException(msg, e);
        }
    }

    @Override
    public R apply(H header) {
        return locate(header);
    }
}