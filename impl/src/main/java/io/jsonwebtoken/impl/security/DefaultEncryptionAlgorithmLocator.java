package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.EncryptionAlgorithm;
import io.jsonwebtoken.security.EncryptionAlgorithmLocator;
import io.jsonwebtoken.security.EncryptionAlgorithms;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultEncryptionAlgorithmLocator implements EncryptionAlgorithmLocator {

    @Override
    public EncryptionAlgorithm getEncryptionAlgorithm(JweHeader jweHeader) {

        String enc = Strings.clean(jweHeader.getEncryptionAlgorithm());
        //TODO: this check needs to be in the parser, to be enforced regardless of the locator implementation
        if (enc == null) {
            String msg = "JWE header does not contain an 'enc' header parameter.  This header parameter is mandatory " +
                "per the JWE Specification, Section 4.1.2. See " +
                "https://tools.ietf.org/html/rfc7516#section-4.1.2 for more information.";
            throw new MalformedJwtException(msg);
        }

        try {
            return EncryptionAlgorithms.forName(enc); //TODO: change to findByName and let the parser throw on null return.  See below:
        } catch (IllegalArgumentException e) {
            //TODO: move this check to the parser - needs to be enforced if the locator returns null or throws a non-JWT exception
            //couldn't find one:
            String msg = "JWE 'enc' header parameter value of '" + enc + "' does not match a JWE standard algorithm " +
                "identifier.  If '" + enc + "' represents a custom algorithm, the JwtParser must be configured with " +
                "a custom EncryptionAlgorithmLocator instance that knows how to return a compatible " +
                "EncryptionAlgorithm instance.  Otherwise, this JWE is invalid and may not be used safely.";
            throw new UnsupportedJwtException(msg, e);
        }
    }
}
