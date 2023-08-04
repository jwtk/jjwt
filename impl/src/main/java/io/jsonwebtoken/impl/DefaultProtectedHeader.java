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

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.impl.security.AbstractAsymmetricJwk;
import io.jsonwebtoken.impl.security.AbstractJwk;
import io.jsonwebtoken.impl.security.JwkConverter;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.PublicJwk;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Header implementation satisfying shared JWS and JWE header parameter requirements.  Header parameters specific to
 * either JWE or JWS will be defined in respective subclasses.
 *
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultProtectedHeader extends DefaultHeader implements ProtectedHeader {

    static final Field<URI> JKU = Fields.uri("jku", "JWK Set URL");

    @SuppressWarnings("unchecked")
    static final Field<PublicJwk<?>> JWK = Fields.builder((Class<PublicJwk<?>>) (Class<?>) PublicJwk.class)
            .setId("jwk").setName("JSON Web Key")
            .setConverter(JwkConverter.PUBLIC_JWK).build();
    static final Field<Set<String>> CRIT = Fields.stringSet("crit", "Critical");

    static final Field<String> KID = AbstractJwk.KID;

    static final Field<URI> X5U = AbstractAsymmetricJwk.X5U;

    static final Field<List<X509Certificate>> X5C = AbstractAsymmetricJwk.X5C;

    static final Field<byte[]> X5T = AbstractAsymmetricJwk.X5T;

    static final Field<byte[]> X5T_S256 = AbstractAsymmetricJwk.X5T_S256;

    static final Registry<String, Field<?>> FIELDS =
            Fields.registry(DefaultHeader.FIELDS, CRIT, JKU, JWK, KID, X5U, X5C, X5T, X5T_S256);

    static boolean isCandidate(FieldMap fields) {
        String id = fields.get(DefaultHeader.ALGORITHM);
        return (Strings.hasText(id) && !Jwts.SIG.NONE.equals(Jwts.SIG.get().get(id))) ||
                fields.get(JKU) != null ||
                fields.get(JWK) != null ||
                !Collections.isEmpty(fields.get(CRIT)) ||
                Strings.hasText(fields.get(KID)) ||
                fields.get(X5U) != null ||
                !Collections.isEmpty(fields.get(X5C)) ||
                !Bytes.isEmpty(fields.get(X5T)) ||
                !Bytes.isEmpty(fields.get(X5T_S256));
    }

    protected DefaultProtectedHeader(Registry<String, Field<?>> fields, Map<String, ?> values) {
        super(fields, values);
    }

    @Override
    public String getKeyId() {
        return get(KID);
    }

    @Override
    public URI getJwkSetUrl() {
        return get(JKU);
    }

    @Override
    public PublicJwk<?> getJwk() {
        return get(JWK);
    }

    @Override
    public URI getX509Url() {
        return get(AbstractAsymmetricJwk.X5U);
    }

    @Override
    public List<X509Certificate> getX509CertificateChain() {
        return get(X5C);
    }

    @Override
    public byte[] getX509CertificateSha1Thumbprint() {
        return get(X5T);
    }

    @Override
    public byte[] getX509CertificateSha256Thumbprint() {
        return get(X5T_S256);
    }

    @Override
    public Set<String> getCritical() {
        return get(CRIT);
    }
}
