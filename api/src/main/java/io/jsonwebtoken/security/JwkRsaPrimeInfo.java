package io.jsonwebtoken.security;

import java.util.Map;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkRsaPrimeInfo extends Map<String,Object>, JwkRsaPrimeInfoMutator<JwkRsaPrimeInfo> {

    String getPrime();

    String getCrtExponent();

    String getCrtCoefficient();

}
