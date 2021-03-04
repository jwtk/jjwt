package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.PrivateEcJwk;

class DefaultPrivateEcJwk extends AbstractEcJwk<PrivateEcJwk> implements PrivateEcJwk {

    static final String D = "d";

    @Override
    public String getD() {
        return getString(D);
    }

    @Override
    public PrivateEcJwk setD(String d) {
        return setRequiredValue(D, d, "private key");
    }
}
