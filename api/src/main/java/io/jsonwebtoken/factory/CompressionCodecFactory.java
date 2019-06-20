package io.jsonwebtoken.factory;

import io.jsonwebtoken.CompressionCodec;

/**
 * Factory for {@link CompressionCodec} implementations. Backs the {@link io.jsonwebtoken.CompressionCodecs} constants
 * class. Implementations of jjwt-api should provide their own implementation and make it available via a provider
 * configuration file in META-INF/services.
 */
public interface CompressionCodecFactory {

    /**
     * Creates a new instance of a CompressionCodec implementing the <a href="https://tools.ietf.org/html/rfc7518">JWA</a>
     * standard <a href="https://en.wikipedia.org/wiki/DEFLATE">deflate</a> compression algorithm
     *
     * @return A new instance of a deflate CompressionCodec
     */
    CompressionCodec deflateCodec();

    /**
     * Creates a new instance of a CompressionCodec implementing the <a href="https://en.wikipedia.org/wiki/Gzip">gzip</a>
     * compression algorithm. * <h3>Compatibility Warning</h3> * <p><b>This is not a standard JWA compression
     * algorithm</b>.  Be sure to use this only when you are confident * that all parties accessing the token support
     * the gzip algorithm.</p> * <p>If you're concerned about compatibility, the {@link #deflateCodec()} code is JWA
     * standards-compliant.</p>
     *
     * @return A new instance of a gzip CompressionCodec
     */
    CompressionCodec gzipCodec();
}
