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
import io.jsonwebtoken.JweHeaderMutator;
import io.jsonwebtoken.impl.lang.Converters;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.impl.lang.PositiveIntegerConverter;
import io.jsonwebtoken.impl.lang.RequiredBitLengthConverter;
import io.jsonwebtoken.impl.security.JwkConverter;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.PublicJwk;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Header implementation satisfying JWE header parameter requirements.
 *
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultJweHeader extends AbstractProtectedHeader<DefaultJweHeader> implements JweHeader, JweHeaderMutator<DefaultJweHeader> {

    static final Field<String> ENCRYPTION_ALGORITHM = Fields.string("enc", "Encryption Algorithm");

    @SuppressWarnings("unchecked")
    public static final Field<PublicJwk<?>> EPK = Fields.builder((Class<PublicJwk<?>>) (Class<?>) PublicJwk.class)
            .setId("epk").setName("Ephemeral Public Key")
            .setConverter(JwkConverter.PUBLIC_JWK).build();
    static final Field<byte[]> APU = Fields.bytes("apu", "Agreement PartyUInfo").build();
    static final Field<byte[]> APV = Fields.bytes("apv", "Agreement PartyVInfo").build();

    // https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.1 says 96 bits required:
    public static final Field<byte[]> IV = Fields.bytes("iv", "Initialization Vector")
            .setConverter(new RequiredBitLengthConverter(Converters.BASE64URL_BYTES, 96)).build();

    // https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.2 says 128 bits required:
    public static final Field<byte[]> TAG = Fields.bytes("tag", "Authentication Tag")
            .setConverter(new RequiredBitLengthConverter(Converters.BASE64URL_BYTES, 128)).build();

    // https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.1 says at least 64 bits (8 bytes) is required:
    public static final Field<byte[]> P2S = Fields.bytes("p2s", "PBES2 Salt Input")
            .setConverter(new RequiredBitLengthConverter(Converters.BASE64URL_BYTES, 64, false)).build();
    public static final Field<Integer> P2C = Fields.builder(Integer.class)
            .setConverter(PositiveIntegerConverter.INSTANCE).setId("p2c").setName("PBES2 Count").build();

    static final Registry<String, Field<?>> FIELDS =
            Fields.registry(AbstractProtectedHeader.FIELDS, ENCRYPTION_ALGORITHM, EPK, APU, APV, IV, TAG, P2S, P2C);

    public DefaultJweHeader() {
        super(FIELDS);
    }

    public DefaultJweHeader(Map<String, ?> map) {
        super(FIELDS, map);
    }

    @Override
    public String getName() {
        return "JWE header";
    }

    @Override
    public String getEncryptionAlgorithm() {
        return idiomaticGet(ENCRYPTION_ALGORITHM);
    }

    @Override
    public PublicJwk<?> getEphemeralPublicKey() {
        return idiomaticGet(EPK);
    }

    @Override
    public byte[] getAgreementPartyUInfo() {
        return idiomaticGet(APU);
    }

    @Override
    public DefaultJweHeader setAgreementPartyUInfo(byte[] info) {
        put(APU, info);
        return this;
    }

    @Override
    public DefaultJweHeader setAgreementPartyUInfo(String info) {
        byte[] bytes = Strings.hasText(info) ? info.getBytes(StandardCharsets.UTF_8) : null;
        return setAgreementPartyUInfo(bytes);
    }

    @Override
    public byte[] getAgreementPartyVInfo() {
        return idiomaticGet(APV);
    }

    @Override
    public DefaultJweHeader setAgreementPartyVInfo(byte[] info) {
        put(APV, info);
        return this;
    }

    @Override
    public DefaultJweHeader setAgreementPartyVInfo(String info) {
        byte[] bytes = Strings.hasText(info) ? info.getBytes(StandardCharsets.UTF_8) : null;
        return setAgreementPartyVInfo(bytes);
    }

    @Override
    public byte[] getInitializationVector() {
        return idiomaticGet(IV);
    }

    @Override
    public byte[] getAuthenticationTag() {
        return idiomaticGet(TAG);
    }

    public byte[] getPbes2Salt() {
        return idiomaticGet(P2S);
    }

    @Override
    public Integer getPbes2Count() {
        return idiomaticGet(P2C);
    }

    @Override
    public DefaultJweHeader setPbes2Count(int count) {
        put(P2C, count);
        return this;
    }
}
