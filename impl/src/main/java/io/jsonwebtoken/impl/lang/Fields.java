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
import io.jsonwebtoken.lang.Registry;

import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class Fields {

    private Fields() { // prevent instantiation
    }

    public static Field<String> string(String id, String name) {
        return builder(String.class).setId(id).setName(name).build();
    }

    public static Field<Date> rfcDate(String id, String name) {
        return builder(Date.class).setConverter(JwtDateConverter.INSTANCE).setId(id).setName(name).build();
    }

    public static Field<List<X509Certificate>> x509Chain(String id, String name) {
        return builder(X509Certificate.class)
                .setConverter(Converters.X509_CERTIFICATE).list()
                .setId(id).setName(name).build();
    }

    public static <T> FieldBuilder<T> builder(Class<T> type) {
        return new DefaultFieldBuilder<>(type);
    }

    public static Field<Set<String>> stringSet(String id, String name) {
        return builder(String.class).set().setId(id).setName(name).build();
    }

    public static Field<URI> uri(String id, String name) {
        return builder(URI.class).setConverter(Converters.URI).setId(id).setName(name).build();
    }

    public static FieldBuilder<byte[]> bytes(String id, String name) {
        return builder(byte[].class).setConverter(Converters.BASE64URL_BYTES).setId(id).setName(name);
    }

    public static FieldBuilder<BigInteger> bigInt(String id, String name) {
        return builder(BigInteger.class).setConverter(Converters.BIGINT).setId(id).setName(name);
    }

    public static Field<BigInteger> secretBigInt(String id, String name) {
        return bigInt(id, name).setSecret(true).build();
    }

    public static Registry<String, Field<?>> registry(Field<?>... fields) {
        return registry(Arrays.asList(fields));
    }

    public static Registry<String, Field<?>> registry(Collection<Field<?>> fields) {
        return new IdRegistry<>("Field", fields, true);
    }

    public static Registry<String, Field<?>> registry(Registry<String, Field<?>> parent, Field<?>... fields) {
        Set<Field<?>> set = new LinkedHashSet<>(parent.size() + fields.length);
        set.addAll(parent.values());
        set.addAll(Arrays.asList(fields));
        return new IdRegistry<>("Field", set, true);
    }
}
