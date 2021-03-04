package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.JwkRsaPrimeInfo;
import io.jsonwebtoken.security.PrivateRsaJwk;

import java.util.List;

public class DefaultPrivateRsaJwk extends AbstractRsaJwk<PrivateRsaJwk> implements PrivateRsaJwk {

    static String PRIVATE_EXPONENT = "d";
    static String FIRST_PRIME = "p";
    static String SECOND_PRIME = "q";
    static String FIRST_CRT_EXPONENT = "dp";
    static String SECOND_CRT_EXPONENT = "dq";
    static String FIRST_CRT_COEFFICIENT = "qi";
    static String OTHER_PRIMES_INFO = "oth";

    @Override
    public String getD() {
        return getString(PRIVATE_EXPONENT);
    }

    @Override
    public PrivateRsaJwk setD(String d) {
        return setRequiredValue(PRIVATE_EXPONENT, d, "private exponent");
    }

    @Override
    public String getP() {
        return getString(FIRST_PRIME);
    }

    @Override
    public PrivateRsaJwk setP(String p) {
        return setRequiredValue(FIRST_PRIME, p, "first prime factor");
    }

    @Override
    public String getQ() {
        return getString(SECOND_PRIME);
    }

    @Override
    public PrivateRsaJwk setQ(String q) {
        return setRequiredValue(FIRST_PRIME, q, "second prime factor");
    }

    @Override
    public String getDP() {
        return getString(FIRST_CRT_EXPONENT);
    }

    @Override
    public PrivateRsaJwk setDP(String dp) {
        return setRequiredValue(FIRST_CRT_EXPONENT, dp, "first crt exponent");
    }

    @Override
    public String getDQ() {
        return getString(SECOND_CRT_EXPONENT);
    }

    @Override
    public PrivateRsaJwk setDQ(String dq) {
        return setRequiredValue(SECOND_CRT_EXPONENT, dq, "second crt exponent");
    }

    @Override
    public String getQI() {
        return getString(FIRST_CRT_COEFFICIENT);
    }

    @Override
    public PrivateRsaJwk setQI(String qi) {
        return setRequiredValue(FIRST_CRT_COEFFICIENT, qi, "first crt coefficient");
    }

    @Override
    public List<JwkRsaPrimeInfo> getOtherPrimesInfo() {
        throw new UnsupportedOperationException("Not yet implemented.");
    }

    @Override
    public PrivateRsaJwk setOtherPrimesInfo(List<JwkRsaPrimeInfo> infos) {
        throw new UnsupportedOperationException("Not yet implemented.");
    }
}
