/*
 * Copyright (C) 2019 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken

import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.jackson.io.JacksonDeserializer
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotNull

class CustomObjectDeserializationTest {

    /**
     * Test parsing without and then with a custom deserializer. Ensures custom type is parsed from claims
     */
    @Test
    void testCustomObjectDeserialization() {

        CustomBean customBean = new CustomBean()
        customBean.key1 = "value1"
        customBean.key2 = 42

        String jwtString = Jwts.builder().claim("cust", customBean).compact()

        // no custom deserialization, object is a map
        Jwt<Header, Claims> jwt = Jwts.parser().enableUnsecured().build().parseClaimsJwt(jwtString)
        assertNotNull jwt
        assertEquals jwt.getPayload().get('cust'), [key1: 'value1', key2: 42]

        // custom type for 'cust' claim
        Deserializer deserializer = new JacksonDeserializer([cust: CustomBean])
        jwt = Jwts.parser().enableUnsecured().deserializeJsonWith(deserializer).build().parseClaimsJwt(jwtString)
        assertNotNull jwt
        CustomBean result = jwt.getPayload().get("cust", CustomBean)
        assertEquals customBean, result
    }

    static class CustomBean {
        private String key1
        private Integer key2

        String getKey1() {
            return key1
        }

        void setKey1(String key1) {
            this.key1 = key1
        }

        Integer getKey2() {
            return key2
        }

        void setKey2(Integer key2) {
            this.key2 = key2
        }

        boolean equals(o) {
            if (this.is(o)) return true
            if (getClass() != o.class) return false

            CustomBean that = (CustomBean) o

            if (key1 != that.key1) return false
            if (key2 != that.key2) return false

            return true
        }

        int hashCode() {
            int result
            result = (key1 != null ? key1.hashCode() : 0)
            result = 31 * result + (key2 != null ? key2.hashCode() : 0)
            return result
        }
    }
}
