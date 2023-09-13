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
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.Parameters;
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

    static final Parameter<URI> JKU = Parameters.uri("jku", "JWK Set URL");

    static final Parameter<PublicJwk<?>> JWK = Parameters.builder(JwkConverter.PUBLIC_JWK_CLASS)
            .setId("jwk").setName("JSON Web Key")
            .setConverter(JwkConverter.PUBLIC_JWK).build();
    static final Parameter<Set<String>> CRIT = Parameters.stringSet("crit", "Critical");

    static final Parameter<String> KID = AbstractJwk.KID;

    static final Parameter<URI> X5U = AbstractAsymmetricJwk.X5U;

    static final Parameter<List<X509Certificate>> X5C = AbstractAsymmetricJwk.X5C;

    static final Parameter<byte[]> X5T = AbstractAsymmetricJwk.X5T;

    static final Parameter<byte[]> X5T_S256 = AbstractAsymmetricJwk.X5T_S256;

    static final Registry<String, Parameter<?>> PARAMS =
            Parameters.registry(DefaultHeader.PARAMS, CRIT, JKU, JWK, KID, X5U, X5C, X5T, X5T_S256);

    static boolean isCandidate(ParameterMap map) {
        String id = map.get(DefaultHeader.ALGORITHM);
        return (Strings.hasText(id) && !Jwts.SIG.NONE.equals(Jwts.SIG.get().get(id))) ||
                map.get(JKU) != null ||
                map.get(JWK) != null ||
                !Collections.isEmpty(map.get(CRIT)) ||
                Strings.hasText(map.get(KID)) ||
                map.get(X5U) != null ||
                !Collections.isEmpty(map.get(X5C)) ||
                !Bytes.isEmpty(map.get(X5T)) ||
                !Bytes.isEmpty(map.get(X5T_S256));
    }

    protected DefaultProtectedHeader(Registry<String, Parameter<?>> registry, Map<String, ?> values) {
        super(registry, values);
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
