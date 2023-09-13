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

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.Converters;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.impl.lang.PositiveIntegerConverter;
import io.jsonwebtoken.impl.lang.RequiredBitLengthConverter;
import io.jsonwebtoken.impl.security.JwkConverter;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.PublicJwk;

import java.util.Map;

/**
 * Header implementation satisfying JWE header parameter requirements.
 *
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultJweHeader extends DefaultProtectedHeader implements JweHeader {

    static final Parameter<String> ENCRYPTION_ALGORITHM = Parameters.string("enc", "Encryption Algorithm");

    public static final Parameter<PublicJwk<?>> EPK = Parameters.builder(JwkConverter.PUBLIC_JWK_CLASS)
            .setId("epk").setName("Ephemeral Public Key")
            .setConverter(JwkConverter.PUBLIC_JWK).build();
    static final Parameter<byte[]> APU = Parameters.bytes("apu", "Agreement PartyUInfo").build();
    static final Parameter<byte[]> APV = Parameters.bytes("apv", "Agreement PartyVInfo").build();

    // https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.1 says 96 bits required:
    public static final Parameter<byte[]> IV = Parameters.bytes("iv", "Initialization Vector")
            .setConverter(new RequiredBitLengthConverter(Converters.BASE64URL_BYTES, 96)).build();

    // https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.2 says 128 bits required:
    public static final Parameter<byte[]> TAG = Parameters.bytes("tag", "Authentication Tag")
            .setConverter(new RequiredBitLengthConverter(Converters.BASE64URL_BYTES, 128)).build();

    // https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.1 says at least 64 bits (8 bytes) is required:
    public static final Parameter<byte[]> P2S = Parameters.bytes("p2s", "PBES2 Salt Input")
            .setConverter(new RequiredBitLengthConverter(Converters.BASE64URL_BYTES, 64, false)).build();
    public static final Parameter<Integer> P2C = Parameters.builder(Integer.class)
            .setConverter(PositiveIntegerConverter.INSTANCE).setId("p2c").setName("PBES2 Count").build();

    static final Registry<String, Parameter<?>> PARAMS =
            Parameters.registry(DefaultProtectedHeader.PARAMS, ENCRYPTION_ALGORITHM, EPK, APU, APV, IV, TAG, P2S, P2C);

    static boolean isCandidate(ParameterMap map) {
        return Strings.hasText(map.get(ENCRYPTION_ALGORITHM)) || // MUST have at least an `enc` header
                !Collections.isEmpty(map.get(EPK)) ||
                !Bytes.isEmpty(map.get(APU)) ||
                !Bytes.isEmpty(map.get(APV)) ||
                !Bytes.isEmpty(map.get(IV)) ||
                !Bytes.isEmpty(map.get(TAG)) ||
                !Bytes.isEmpty(map.get(P2S)) ||
                (map.get(P2C) != null && map.get(P2C) > 0);
    }

    public DefaultJweHeader(Map<String, ?> map) {
        super(PARAMS, map);
    }

    @Override
    public String getName() {
        return "JWE header";
    }

    @Override
    public String getEncryptionAlgorithm() {
        return get(ENCRYPTION_ALGORITHM);
    }

    @Override
    public PublicJwk<?> getEphemeralPublicKey() {
        return get(EPK);
    }

    @Override
    public byte[] getAgreementPartyUInfo() {
        return get(APU);
    }

    @Override
    public byte[] getAgreementPartyVInfo() {
        return get(APV);
    }

    @Override
    public byte[] getInitializationVector() {
        return get(IV);
    }

    @Override
    public byte[] getAuthenticationTag() {
        return get(TAG);
    }

    public byte[] getPbes2Salt() {
        return get(P2S);
    }

    @Override
    public Integer getPbes2Count() {
        return get(P2C);
    }
}
