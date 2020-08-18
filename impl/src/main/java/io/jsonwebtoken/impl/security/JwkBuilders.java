package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.ProtoJwkBuilder;

// Implementation bridge to concrete implementations so the API module doesn't need to know their
// internals.  The API module just needs to call this class via reflection, and the internal Classes/Subclasses
// can change without requiring an API module change.
public final class JwkBuilders {

    private JwkBuilders() {
    }

    public static ProtoJwkBuilder<?,?,?> builder() {
        return new DefaultProtoJwkBuilder<>();
    }
}
