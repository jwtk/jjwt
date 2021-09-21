package io.jsonwebtoken.impl;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

public class IdLocator<H extends Header<H>, R> implements Function<H, R> {

    private final String headerName;
    private final String requiredMsg;
    private final boolean headerValueRequired;
    private final Function<String, R> primary;
    private final Function<H, R> backup;

    public IdLocator(String headerName, String requiredMsg, Function<String, R> primary, Function<H, R> backup) {
        this.headerName = Assert.hasText(headerName, "Header name cannot be null or empty.");
        this.requiredMsg = requiredMsg;
        this.headerValueRequired = Strings.hasText(requiredMsg);
        this.primary = Assert.notNull(primary, "Primary lookup function cannot be null.");
        this.backup = Assert.notNull(backup, "Backup locator cannot be null.");
    }

    private static String type(Header<?> header) {
        if (header instanceof JweHeader) {
            return "JWE";
        } else if (header instanceof JwsHeader) {
            return "JWS";
        } else {
            return "JWT";
        }
    }

    @Override
    public R apply(H header) {

        Assert.notNull(header, "Header argument cannot be null.");

        Object val = header.get(this.headerName);
        String id = val != null ? String.valueOf(val) : null;

        if (this.headerValueRequired && !Strings.hasText(id)) {
            throw new MalformedJwtException(requiredMsg);
        }

        R instance = primary.apply(id);
        if (instance == null) {
            instance = backup.apply(header);
        }

        if (this.headerValueRequired && instance == null) {
            String msg = "Unrecognized " + type(header) + " '" + this.headerName + "' header value: " + id;
            throw new UnsupportedJwtException(msg);
        }

        return instance;
    }
}