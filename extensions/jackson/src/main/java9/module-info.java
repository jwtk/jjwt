module io.jsonwebtoken.jjwt.ext.jackson {
    requires transitive com.fasterxml.jackson.core;
    requires transitive com.fasterxml.jackson.databind;
    requires io.jsonwebtoken.jjwt.api;

    exports io.jsonwebtoken.jackson.io;

    provides io.jsonwebtoken.io.Deserializer with
            io.jsonwebtoken.jackson.io.JacksonDeserializer;
    provides io.jsonwebtoken.io.Serializer with
            io.jsonwebtoken.jackson.io.JacksonSerializer;

}
