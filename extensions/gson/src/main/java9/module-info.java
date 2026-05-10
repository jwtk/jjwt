module io.jsonwebtoken.jjwt.ext.gson {
    requires transitive com.google.gson;
    requires io.jsonwebtoken.jjwt.api;

    exports io.jsonwebtoken.gson.io;

    provides io.jsonwebtoken.io.Deserializer with
            io.jsonwebtoken.gson.io.GsonDeserializer;
    provides io.jsonwebtoken.io.Serializer with
            io.jsonwebtoken.gson.io.GsonSerializer;
}
