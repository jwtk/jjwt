package io.jsonwebtoken.security;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.lang.Assert;

public abstract class LocatorAdapter<H extends Header<H>, R> implements Locator<H, R> {

    @Override
    public final R locate(H header) {
        Assert.notNull(header, "Header cannot be null.");
        if (header instanceof JwsHeader) {
            return locate((JwsHeader) header);
        } else if (header instanceof JweHeader) {
            return locate((JweHeader) header);
        } else {
            return doLocate(header);
        }
    }

    protected R locate(JweHeader header) {
        return null;
    }

    protected R locate(JwsHeader header) {
        return null;
    }

    protected R doLocate(Header<?> header) {
        return null;
    }
}
