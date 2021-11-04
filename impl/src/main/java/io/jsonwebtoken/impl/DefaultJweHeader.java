package io.jsonwebtoken.impl;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultJweHeader extends DefaultHeader<JweHeader> implements JweHeader {

    static final Field<String> ENCRYPTION_ALGORITHM = Fields.string("enc", "Encryption Algorithm");
    public static final Field<Integer> P2C = Fields.builder(Integer.class).setId("p2c").setName("PBES2 Count").build();
    public static final Field<byte[]> P2S = Fields.bytes("p2s", "PBES2 Salt Input").build();
    static final Field<byte[]> APU = Fields.bytes("apu", "Agreement PartyUInfo").build();
    static final Field<byte[]> APV = Fields.bytes("apv", "Agreement PartyVInfo").build();

    static final Set<Field<?>> FIELDS = Collections.concat(CHILD_FIELDS, ENCRYPTION_ALGORITHM, P2C, P2S, APU, APV);

    public DefaultJweHeader() {
        super(FIELDS);
    }

    public DefaultJweHeader(Map<String, ?> map) {
        super(FIELDS, map);
    }

    @Override
    public String getEncryptionAlgorithm() {
        return idiomaticGet(ENCRYPTION_ALGORITHM);
    }

//    @Override
//    public JweHeader setEncryptionAlgorithm(String enc) {
//        put(ENCRYPTION_ALGORITHM.getId(), enc);
//        return this;
//    }

    @Override
    public int getPbes2Count() {
        return idiomaticGet(P2C);
    }

    @Override
    public JweHeader setPbes2Count(int count) {
        put(P2C.getId(), count);
        return this;
    }

    public byte[] getPbes2Salt() {
        return idiomaticGet(P2S);
    }

    public JweHeader setPbes2Salt(byte[] salt) {
        put(P2S.getId(), salt);
        return this;
    }

    @Override
    public byte[] getAgreementPartyUInfo() {
        return idiomaticGet(APU);
    }

    @Override
    public String getAgreementPartyUInfoString() {
        byte[] bytes = getAgreementPartyUInfo();
        return Arrays.length(bytes) == 0 ? null : new String(bytes, StandardCharsets.UTF_8);
    }

    @Override
    public JweHeader setAgreementPartyUInfo(byte[] info) {
        put(APU.getId(), info);
        return this;
    }

    @Override
    public JweHeader setAgreementPartyUInfo(String info) {
        byte[] bytes = Strings.hasText(info) ? info.getBytes(StandardCharsets.UTF_8) : null;
        return setAgreementPartyUInfo(bytes);
    }

    @Override
    public byte[] getAgreementPartyVInfo() {
        return idiomaticGet(APV);
    }

    @Override
    public String getAgreementPartyVInfoString() {
        byte[] bytes = getAgreementPartyVInfo();
        return Arrays.length(bytes) == 0 ? null : new String(bytes, StandardCharsets.UTF_8);
    }

    @Override
    public JweHeader setAgreementPartyVInfo(byte[] info) {
        put(APV.getId(), info);
        return this;
    }

    @Override
    public JweHeader setAgreementPartyVInfo(String info) {
        byte[] bytes = Strings.hasText(info) ? info.getBytes(StandardCharsets.UTF_8) : null;
        return setAgreementPartyVInfo(bytes);
    }
}
