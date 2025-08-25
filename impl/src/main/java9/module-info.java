module io.jsonwebtoken.jjwt.impl {
    requires io.jsonwebtoken.jjwt.api;

    exports io.jsonwebtoken.impl;
    exports io.jsonwebtoken.impl.compression;
    exports io.jsonwebtoken.impl.lang;

    provides io.jsonwebtoken.CompressionCodec with
            io.jsonwebtoken.impl.compression.DeflateCompressionAlgorithm,
            io.jsonwebtoken.impl.compression.GzipCompressionAlgorithm;

    uses io.jsonwebtoken.CompressionCodec;
    uses io.jsonwebtoken.io.Deserializer;
    uses io.jsonwebtoken.io.Serializer;
}
