package io.jsonwebtoken.security;

import javax.crypto.SecretKey;
import java.util.Map;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyResult extends PayloadSupplier<byte[]>, KeySupplier<SecretKey> {

    Map<String,?> getHeaderParams();
}
