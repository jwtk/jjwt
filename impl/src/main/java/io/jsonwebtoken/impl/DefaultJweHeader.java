package io.jsonwebtoken.impl;

import io.jsonwebtoken.JweHeader;

import java.util.Map;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultJweHeader extends DefaultHeader<JweHeader> implements JweHeader {

    public DefaultJweHeader() {
        super();
    }

    public DefaultJweHeader(Map<String, ?> map) {
        super(map);
    }

    @Override
    public String getEncryptionAlgorithm() {
        return getString(ENCRYPTION_ALGORITHM);
    }

    @Override
    public JweHeader setEncryptionAlgorithm(String enc) {
        setValue(ENCRYPTION_ALGORITHM, enc);
        return this;
    }
}
