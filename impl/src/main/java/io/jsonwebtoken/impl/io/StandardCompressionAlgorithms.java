package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.impl.compression.DeflateCompressionAlgorithm;
import io.jsonwebtoken.impl.compression.GzipCompressionAlgorithm;
import io.jsonwebtoken.impl.lang.DelegatingRegistry;
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.lang.Collections;

@SuppressWarnings("unused") // used via reflection in io.jsonwebtoken.Jwts.ZIP
public final class StandardCompressionAlgorithms extends DelegatingRegistry<String, CompressionAlgorithm> {

    public StandardCompressionAlgorithms() {
        super(new IdRegistry<>("Compression Algorithm", Collections.<CompressionAlgorithm>of(
                new DeflateCompressionAlgorithm(),
                new GzipCompressionAlgorithm()
        ), false));
    }
}
