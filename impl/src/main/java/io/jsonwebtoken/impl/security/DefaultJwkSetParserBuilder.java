package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.security.JwkSet;

public class DefaultJwkSetParserBuilder extends AbstractJwkParserBuilder<JwkSet, DefaultJwkSetParserBuilder> {
    @Override
    protected Parser<JwkSet> doBuild() {
        return new DefaultJwkSetParser(this.provider, this.deserializer, this.operationPolicy);
    }
}
