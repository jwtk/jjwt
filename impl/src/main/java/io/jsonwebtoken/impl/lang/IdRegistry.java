/*
 * Copyright © 2022 jsonwebtoken.io
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
package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;

public class IdRegistry<T extends Identifiable> extends StringRegistry<T> {

    public static final Function<Identifiable, String> FN = new Function<Identifiable, String>() {
        @Override
        public String apply(Identifiable identifiable) {
            Assert.notNull(identifiable, "Identifiable argument cannot be null.");
            return Assert.notNull(Strings.clean(identifiable.getId()), "Identifier cannot be null or empty.");
        }
    };

    @SuppressWarnings("unchecked")
    public static <T extends Identifiable> Function<T, String> fn() {
        return (Function<T, String>) FN;
    }

    public IdRegistry(String name, Collection<T> instances) {
        // Each registry requires CaSe-SeNsItIvE keys by default purpose - all JWA standard algorithm identifiers
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
        this(name, instances, true); // <---
    }

    public IdRegistry(String name, Collection<T> instances, boolean caseSensitive) {
        super(name, "id",
                Assert.notEmpty(instances, "Collection of Identifiable instances may not be null or empty."),
                IdRegistry.<T>fn(),
                caseSensitive);
    }
}
