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

import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.Functions;
import io.jsonwebtoken.impl.lang.OptionalMethodInvoker;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public class NamedParameterSpecValueFinder implements Function<Key, String> {

    private static final Function<Key, AlgorithmParameterSpec> EDEC_KEY_GET_PARAMS =
            new OptionalMethodInvoker<>("java.security.interfaces.EdECKey", "getParams"); // >= JDK 15
    private static final Function<Key, AlgorithmParameterSpec> XEC_KEY_GET_PARAMS =
            new OptionalMethodInvoker<>("java.security.interfaces.XECKey", "getParams"); // >= JDK 11
    private static final Function<Object, String> GET_NAME =
            new OptionalMethodInvoker<>("java.security.spec.NamedParameterSpec", "getName"); // >= JDK 11

    private static final Function<Key, String> COMPOSED = Functions.andThen(Functions.firstResult(EDEC_KEY_GET_PARAMS, XEC_KEY_GET_PARAMS), GET_NAME);

    @Override
    public String apply(final Key key) {
        return COMPOSED.apply(key);
    }
}
