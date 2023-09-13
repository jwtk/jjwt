/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.lang

import io.jsonwebtoken.impl.security.Randoms
import org.junit.Test

import java.security.MessageDigest

import static org.junit.Assert.*

class BytesTest {

    static final Random RANDOM = Randoms.secureRandom()

    static final byte[] A = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05] as byte[]
    static final byte[] B = [0x02, 0x03] as byte[]
    static final byte[] C = [0x05, 0x06] as byte[]
    static final byte[] D = [0x06, 0x07] as byte[]

    @Test
    void testPrivateCtor() { // for code coverage only
        new Bytes()
    }

    @Test
    void testRandom() {
        byte[] random = Bytes.random(12)
        assertEquals 12, random.length
    }

    @Test
    void testRandomBits() {
        int count = 16
        byte[] random = Bytes.randomBits(count * Byte.SIZE)
        assertEquals count, random.length
    }

    @Test
    void testRandomBitsZeroLength() {
        try {
            Bytes.randomBits(0)
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals 'numBytes argument must be >= 0', expected.getMessage()
        }
    }

    @Test
    void testRandomBitsNegativeLength() {
        try {
            Bytes.randomBits(-1)
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals 'numBytes argument must be >= 0', expected.getMessage()
        }
    }

    @Test
    void testIntToBytesToInt() {
        int iterations = 10000
        for (int i = 0; i < iterations; i++) {
            int a = RANDOM.nextInt()
            byte[] bytes = Bytes.toBytes(a)
            int b = Bytes.toInt(bytes)
            assertEquals a, b
        }
    }

    @Test
    void testLongToBytesToLong() {
        int iterations = 10000
        for (int i = 0; i < iterations; i++) {
            long a = RANDOM.nextLong()
            byte[] bytes = Bytes.toBytes(a)
            long b = Bytes.toLong(bytes)
            assertEquals a, b
        }
    }

    @Test
    void testConcatNull() {
        byte[] output = Bytes.concat(null)
        assertNotNull output
        assertEquals 0, output.length
    }

    @Test
    void testConcatSingle() {
        byte[] bytes = new byte[32]
        RANDOM.nextBytes(bytes)
        byte[][] arg = [bytes] as byte[][]
        byte[] output = Bytes.concat(arg)
        assertTrue MessageDigest.isEqual(bytes, output)
    }

    @Test
    void testConcatSingleEmpty() {
        byte[] bytes = new byte[0]
        byte[][] arg = [bytes] as byte[][]
        byte[] output = Bytes.concat(arg)
        assertNotNull output
        assertEquals 0, output.length
    }

    @Test
    void testConcatMultiple() {
        byte[] a = new byte[32]; RANDOM.nextBytes(a)
        byte[] b = new byte[16]; RANDOM.nextBytes(b)

        byte[] output = Bytes.concat(a, b)

        assertNotNull output
        assertEquals a.length + b.length, output.length

        byte[] partA = new byte[a.length]
        System.arraycopy(output, 0, partA, 0, a.length)
        assertTrue MessageDigest.isEqual(a, partA)

        byte[] partB = new byte[b.length]
        System.arraycopy(output, a.length, partB, 0, b.length)
        assertTrue MessageDigest.isEqual(b, partB)
    }

    @Test
    void testConcatMultipleWithOneEmpty() {

        byte[] a = new byte[32]; RANDOM.nextBytes(a)
        byte[] b = new byte[0]

        byte[] output = Bytes.concat(a, b)

        assertNotNull output
        assertEquals a.length + b.length, output.length

        byte[] partA = new byte[a.length]
        System.arraycopy(output, 0, partA, 0, a.length)
        assertTrue MessageDigest.isEqual(a, partA)

        byte[] partB = new byte[b.length]
        System.arraycopy(output, a.length, partB, 0, b.length)
        assertTrue MessageDigest.isEqual(b, partB)
    }

    @Test
    void testLength() {
        int len = 32
        assertEquals len, Bytes.length(new byte[len])
    }

    @Test
    void testLengthZero() {
        assertEquals 0, Bytes.length(new byte[0])
    }

    @Test
    void testLengthNull() {
        assertEquals 0, Bytes.length(null)
    }

    @Test
    void testBitLength() {
        int len = 32
        byte[] a = new byte[len]
        assertEquals len * Byte.SIZE, Bytes.bitLength(a)
    }

    @Test
    void testBitLengthZero() {
        assertEquals 0, Bytes.bitLength(new byte[0])
    }

    @Test
    void testBitLengthNull() {
        assertEquals 0, Bytes.bitLength(null)
    }

    @Test
    void testIncrement() {

        byte[] counter = Bytes.toBytes(0)
        for (int i = 0; i < 100; i++) {
            assertEquals i, Bytes.toInt(counter)
            Bytes.increment(counter)
        }

        counter = Bytes.toBytes(Integer.MAX_VALUE - 1)

        Bytes.increment(counter)
        assertEquals Integer.MAX_VALUE, Bytes.toInt(counter)

        //check correct integer overflow:
        Bytes.increment(counter)
        assertEquals Integer.MIN_VALUE, Bytes.toInt(counter)
    }

    @Test
    void testIncrementEmpty() {
        byte[] counter = new byte[0]
        Bytes.increment(counter)
        assertTrue MessageDigest.isEqual(new byte[0], counter)
    }

    @Test
    void testIndexOfFromIndexOOB() {
        int i = Bytes.indexOf(A, 0, A.length, B, 0, B.length, A.length)
        assertEquals(-1, i)
    }

    @Test
    void testIndexOfFromIndexOOBWithZeroLengthTarget() {
        int i = Bytes.indexOf(A, 0, A.length, B, 0, 0, A.length)
        assertEquals(A.length, i)
    }

    @Test
    void testIndexOfFromIndexNegative() {
        int i = Bytes.indexOf(A, 0, A.length, B, 0, B.length, -1) // should normalize fromIndex to be zero
        assertEquals(2, i) // B starts at A index 2
    }

    @Test
    void testIndexOfEmptyTargetIsZero() {
        int i = Bytes.indexOf(A, Bytes.EMPTY)
        assertEquals(0, i)
    }

    @Test
    void testIndexOfOOBSrcIndex() {
        int i = Bytes.indexOf(A, 3, 2, B, 1, A.length, 0)
        assertEquals(-1, i)
    }

    @Test
    void testIndexOfDisjointSrcAndTarget() {
        int i = Bytes.indexOf(A, D)
        assertEquals(-1, i)
    }

    @Test
    void testIndexOfPartialMatch() {
        int i = Bytes.indexOf(A, C)
        assertEquals(-1, i)
    }

    @Test
    void testIndexOfPartialMatchEndDifferent() {
        byte[] toTest = [0x00, 0x01, 0x02, 0x03, 0x04, 0x06] // last byte is different in A
        int i = Bytes.indexOf(A, toTest)
        assertEquals(-1, i)
    }

    @Test
    void testStartsWith() {
        byte[] A = [0x01, 0x02, 0x03]
        byte[] B = [0x01, 0x03]
        byte[] C = [0x02, 0x03]
        assertTrue Bytes.startsWith(A, A, 0)
        assertFalse Bytes.startsWith(A, B)
        assertTrue Bytes.endsWith(A, C)
        assertFalse Bytes.startsWith(A, A, -1)
        assertFalse Bytes.startsWith(C, A)
    }

    @Test
    void testBytesLength() {
        // zero bits means we don't need any bytes:
        assertEquals 0, Bytes.length(0) // zero bits means we don't need any bytes
        assertEquals 1, Bytes.length(1) // one bit needs at least 1 byte
        assertEquals 1, Bytes.length(8) // 8 bits fits into 1 byte
        assertEquals 2, Bytes.length(9) // need at least 2 bytes for 9 bits
        assertEquals 66, Bytes.length(521) // P-521 curve order bit length
    }

    @Test(expected = IllegalArgumentException)
    void testBytesLengthNegative() {
        Bytes.length(-1)
    }

    @Test
    void testClearNull() {
        Bytes.clear(null) // no exception
    }

    @Test
    void testClearEmpty() {
        Bytes.clear(Bytes.EMPTY) // no exception
    }

    @Test
    void testClear() {
        int len = 16
        byte[] bytes = Bytes.random(len)
        boolean allZero = true
        for(int i = 0; i < len; i++) {
            if (bytes[i] != (byte)0) {
                allZero = false
                break
            }
        }
        assertFalse allZero // guarantee that we start with random bytes

        Bytes.clear(bytes)

        allZero = true
        for(int i = 0; i < len; i++) {
            if (bytes[i] != (byte)0) {
                allZero = false
                break
            }
        }
        assertTrue allZero // asserts zeroed out entirely
    }

}
