/*
 * Copyright (C) 2025 jsonwebtoken.io
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
package io.jsonwebtoken.jackson.io.stubs

class CustomBean {

    private String stringValue
    private int intValue
    private Date dateValue
    private short shortValue
    private long longValue
    private byte byteValue
    private byte[] byteArrayValue
    private CustomBean nestedValue

    String getStringValue() {
        return stringValue
    }

    CustomBean setStringValue(String stringValue) {
        this.stringValue = stringValue
        return this
    }

    int getIntValue() {
        return intValue
    }

    CustomBean setIntValue(int intValue) {
        this.intValue = intValue
        return this
    }

    Date getDateValue() {
        return dateValue
    }

    CustomBean setDateValue(Date dateValue) {
        this.dateValue = dateValue
        return this
    }

    short getShortValue() {
        return shortValue
    }

    CustomBean setShortValue(short shortValue) {
        this.shortValue = shortValue
        return this
    }

    long getLongValue() {
        return longValue
    }

    CustomBean setLongValue(long longValue) {
        this.longValue = longValue
        return this
    }

    byte getByteValue() {
        return byteValue
    }

    CustomBean setByteValue(byte byteValue) {
        this.byteValue = byteValue
        return this
    }

    byte[] getByteArrayValue() {
        return byteArrayValue
    }

    CustomBean setByteArrayValue(byte[] byteArrayValue) {
        this.byteArrayValue = byteArrayValue
        return this
    }

    CustomBean getNestedValue() {
        return nestedValue
    }

    CustomBean setNestedValue(CustomBean nestedValue) {
        this.nestedValue = nestedValue
        return this
    }

    boolean equals(o) {
        if (this.is(o)) return true
        if (getClass() != o.class) return false

        CustomBean that = (CustomBean) o

        if (byteValue != that.byteValue) return false
        if (intValue != that.intValue) return false
        if (longValue != that.longValue) return false
        if (shortValue != that.shortValue) return false
        if (!Arrays.equals(byteArrayValue, that.byteArrayValue)) return false
        if (dateValue != that.dateValue) return false
        if (nestedValue != that.nestedValue) return false
        if (stringValue != that.stringValue) return false

        return true
    }

    int hashCode() {
        int result
        result = stringValue.hashCode()
        result = 31 * result + intValue
        result = 31 * result + dateValue.hashCode()
        result = 31 * result + (int) shortValue
        result = 31 * result + (int) (longValue ^ (longValue >>> 32))
        result = 31 * result + (int) byteValue
        result = 31 * result + Arrays.hashCode(byteArrayValue)
        result = 31 * result + nestedValue.hashCode()
        return result
    }


    @Override
    String toString() {
        return "CustomBean{" +
                "stringValue='" + stringValue + '\'' +
                ", intValue=" + intValue +
                ", dateValue=" + dateValue?.time +
                ", shortValue=" + shortValue +
                ", longValue=" + longValue +
                ", byteValue=" + byteValue +
//                ", byteArrayValue=" + Arrays.toString(byteArrayValue) +
                ", nestedValue=" + nestedValue +
                '}'
    }
}
