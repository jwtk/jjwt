package io.jsonwebtoken.impl;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.KeyManagementAlgorithmName;

import java.util.Map;

public class DefaultJweHeader extends DefaultHeader implements JweHeader {

    public DefaultJweHeader() {
        super();
    }

    public DefaultJweHeader(Map<String, Object> map) {
        super(map);
    }

    @Override
    public KeyManagementAlgorithmName getKeyManagementAlgorithm() {
        String value = getString(JweHeader.ALGORITHM);
        if (value != null) {
            return KeyManagementAlgorithmName.forName(value);
        }
        return null;
    }

    @Override
    public JweHeader setKeyManagementAlgorithm(KeyManagementAlgorithmName alg) {
        setValue(ALGORITHM, alg.getValue());
        return this;
    }
}
