package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

/**
 * @since JJWT_RELEASE_VERSION
 */
final class DefaultCurveId implements CurveId {

    private final String id;

    DefaultCurveId(String id) {
        id = Strings.clean(id);
        Assert.hasText(id, "id argument cannot be null or empty.");
        this.id = id;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this || (obj instanceof CurveId && obj.toString().equals(this.id));
    }

    @Override
    public String toString() {
        return id;
    }
}
