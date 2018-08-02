package io.jsonwebtoken.security;

import java.util.List;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface PrivateRsaJwkMutator<T extends PrivateRsaJwkMutator> extends RsaJwkMutator<T> {

    T setD(String d);

    T setP(String p);

    T setQ(String q);

    T setDP(String dp);

    T setDQ(String dq);

    T setQI(String qi);

    T setOtherPrimesInfo(List<JwkRsaPrimeInfo> infos);
}
