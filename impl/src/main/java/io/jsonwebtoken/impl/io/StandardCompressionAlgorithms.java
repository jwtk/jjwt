package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.impl.compression.DeflateCompressionCodec;
import io.jsonwebtoken.impl.compression.GzipCompressionCodec;
import io.jsonwebtoken.impl.lang.DelegatingRegistry;
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.lang.Collections;

@SuppressWarnings("unused") // used via reflection in io.jsonwebtoken.Jwts.ZIP
public final class StandardCompressionAlgorithms extends DelegatingRegistry<String, CompressionCodec> {

    public StandardCompressionAlgorithms() {
        super(new IdRegistry<>("Compression Algorithm", Collections.<CompressionCodec>of(
                new DeflateCompressionCodec(),
                new GzipCompressionCodec()
        ), false));
    }
}
