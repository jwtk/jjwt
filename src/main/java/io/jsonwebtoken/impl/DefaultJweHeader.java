package io.jsonwebtoken.impl;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.KeyManagementAlgorithm;

import java.util.Map;

public class DefaultJweHeader extends DefaultHeader implements JweHeader {

    public DefaultJweHeader() {
        super();
    }

    public DefaultJweHeader(Map<String, Object> map) {
        super(map);
    }

    @Override
    public KeyManagementAlgorithm getKeyManagementAlgorithm() {
        String value = getString(JweHeader.ALGORITHM);
        if (value != null) {
            return KeyManagementAlgorithm.forName(value);
        }
        return null;
    }

    @Override
    public JweHeader setKeyManagementAlgorithm(KeyManagementAlgorithm alg) {
        setValue(ALGORITHM, alg.getValue());
        return this;
    }
}
