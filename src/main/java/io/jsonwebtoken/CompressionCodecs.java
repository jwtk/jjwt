package io.jsonwebtoken;

import io.jsonwebtoken.impl.compression.DeflateCompressionCodec;
import io.jsonwebtoken.impl.compression.GzipCompressionCodec;

/**
 * Provides default implementations of the {@link CompressionCodec} interface.
 *
 * @see #DEFLATE
 * @see #GZIP
 * @since 0.7.0
 */
public final class CompressionCodecs {

    private static final CompressionCodecs INSTANCE = new CompressionCodecs();

    private CompressionCodecs() {} //prevent external instantiation

    /**
     * Codec implementing the <a href="https://tools.ietf.org/html/rfc7518">JWA</a> standard
     * <a href="https://en.wikipedia.org/wiki/DEFLATE">deflate</a> compression algorithm
     */
    public static final CompressionCodec DEFLATE = new DeflateCompressionCodec();

    /**
     * Codec implementing the <a href="https://en.wikipedia.org/wiki/Gzip">gzip</a> compression algorithm.
     * <h3>Compatibility Warning</h3>
     * <p><b>This is not a standard JWA compression algorithm</b>.  Be sure to use this only when you are confident
     * that all parties accessing the token support the gzip algorithm.</p>
     * <p>If you're concerned about compatibility, the {@link #DEFLATE DEFLATE} code is JWA standards-compliant.</p>
     */
    public static final CompressionCodec GZIP = new GzipCompressionCodec();

}
