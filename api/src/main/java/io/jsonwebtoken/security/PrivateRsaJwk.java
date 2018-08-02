package io.jsonwebtoken.security;

import java.util.List;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface PrivateRsaJwk extends RsaJwk<PrivateRsaJwk>, PrivateRsaJwkMutator<PrivateRsaJwk> {

    String getD();

    String getP();

    String getQ();

    String getDP();

    String getDQ();

    String getQI();

    List<JwkRsaPrimeInfo> getOtherPrimesInfo();
}
