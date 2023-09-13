/*
 * Copyright © 2021 jsonwebtoken.io
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

import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Registry;

import java.math.BigInteger;
import java.net.URI;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class Parameters {

    private Parameters() { // prevent instantiation
    }

    public static Parameter<String> string(String id, String name) {
        return builder(String.class).setId(id).setName(name).build();
    }

    public static Parameter<Date> rfcDate(String id, String name) {
        return builder(Date.class).setConverter(JwtDateConverter.INSTANCE).setId(id).setName(name).build();
    }

    public static Parameter<List<X509Certificate>> x509Chain(String id, String name) {
        return builder(X509Certificate.class)
                .setConverter(Converters.X509_CERTIFICATE).list()
                .setId(id).setName(name).build();
    }

    public static <T> ParameterBuilder<T> builder(Class<T> type) {
        return new DefaultParameterBuilder<>(type);
    }

    public static Parameter<Set<String>> stringSet(String id, String name) {
        return builder(String.class).set().setId(id).setName(name).build();
    }

    public static Parameter<URI> uri(String id, String name) {
        return builder(URI.class).setConverter(Converters.URI).setId(id).setName(name).build();
    }

    public static ParameterBuilder<byte[]> bytes(String id, String name) {
        return builder(byte[].class).setConverter(Converters.BASE64URL_BYTES).setId(id).setName(name);
    }

    public static ParameterBuilder<BigInteger> bigInt(String id, String name) {
        return builder(BigInteger.class).setConverter(Converters.BIGINT).setId(id).setName(name);
    }

    public static Parameter<BigInteger> secretBigInt(String id, String name) {
        return bigInt(id, name).setSecret(true).build();
    }

    public static Registry<String, Parameter<?>> registry(Parameter<?>... params) {
        return registry(Arrays.asList(params));
    }

    public static Registry<String, Parameter<?>> registry(Collection<Parameter<?>> params) {
        return new IdRegistry<>("Parameter", params, true);
    }

    public static Registry<String, Parameter<?>> registry(Registry<String, Parameter<?>> parent, Parameter<?>... params) {
        Set<Parameter<?>> set = new LinkedHashSet<>(parent.size() + params.length);
        set.addAll(parent.values());
        set.addAll(Arrays.asList(params));
        return new IdRegistry<>("Parameter", set, true);
    }

    public static Registry<String, ? extends Parameter<?>> replace(Registry<String, ? extends Parameter<?>> registry, Parameter<?> param) {
        Assert.notEmpty(registry, "Registry cannot be null or empty.");
        Assert.notNull(param, "Parameter cannot be null.");
        String id = Assert.hasText(param.getId(), "Parameter id cannot be null or empty.");
        Map<String, Parameter<?>> newParams = new LinkedHashMap<>(registry);
        newParams.remove(id); // remove old/default
        newParams.put(id, param); // add new one
        return registry(newParams.values());
    }

    private static byte[] bytes(BigInteger i) {
        return i != null ? i.toByteArray() : null;
    }

    public static boolean bytesEquals(BigInteger a, BigInteger b) {
        //noinspection NumberEquality
        if (a == b) return true;
        if (a == null || b == null) return false;
        byte[] aBytes = bytes(a);
        byte[] bBytes = bytes(b);
        try {
            return MessageDigest.isEqual(aBytes, bBytes);
        } finally {
            Bytes.clear(aBytes);
            Bytes.clear(bBytes);
        }
    }

    private static <T> boolean equals(T a, T b, Parameter<T> param) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        if (param.isSecret()) {
            // byte[] and BigInteger are the only types of secret Parameters in the JJWT codebase
            // (i.e. Parameter.isSecret() == true). If a Parameter is ever marked as secret, and it's not one of these two
            // data types, we need to know about it.  So we use the 'assertSecret' helper above to ensure we do:
            if (a instanceof byte[]) {
                return b instanceof byte[] && MessageDigest.isEqual((byte[]) a, (byte[]) b);
            } else if (a instanceof BigInteger) {
                return b instanceof BigInteger && bytesEquals((BigInteger) a, (BigInteger) b);
            }
        }
        // default to a standard null-safe comparison:
        return Objects.nullSafeEquals(a, b);
    }

    public static <T> boolean equals(ParameterReadable a, Object o, Parameter<T> param) {
        if (a == o) return true;
        if (a == null || !(o instanceof ParameterReadable)) return false;
        ParameterReadable b = (ParameterReadable) o;
        return equals(a.get(param), b.get(param), param);
    }
}
