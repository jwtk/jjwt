package io.jsonwebtoken.lang;

import io.jsonwebtoken.lang.Objects;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.Timeout;

import java.lang.reflect.Array;

public class ObjectsTest {

    @Rule public final ExpectedException thrown = ExpectedException.none();

    @Rule public final Timeout globalTimeout = new Timeout(10000);

    // Test written by Diffblue Cover.
    @Test
    public void containsConstantInput0NotNullFalseOutputFalse() {

        // Arrange
        final Enum[] enumValues = {};
        final String constant = "a\'b\'c";
        final boolean caseSensitive = false;

        // Act
        final boolean actual = Objects.containsConstant(enumValues, constant, caseSensitive);

        // Assert result
        Assert.assertFalse(actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void containsConstantInput0NotNullOutputFalse() {

        // Arrange
        final Enum[] enumValues = {};
        final String constant = "1a 2b 3c";

        // Act
        final boolean actual = Objects.containsConstant(enumValues, constant);

        // Assert result
        Assert.assertFalse(actual);
    }

    // Test written by Diffblue Cover.

    @Test
    public void containsElementInput0NullOutputFalse() {

        // Arrange
        final Object[] array = {};
        final Object element = null;

        // Act
        final boolean actual = Objects.containsElement(array, element);

        // Assert result
        Assert.assertFalse(actual);
    }

    // Test written by Diffblue Cover.

    @Test
    public void containsElementInput1NegativeOutputFalse() {

        // Arrange
        final Object[] array = {0};
        final Object element = -2_147_483_648;

        // Act
        final boolean actual = Objects.containsElement(array, element);

        // Assert result
        Assert.assertFalse(actual);
    }

    // Test written by Diffblue Cover.

    @Test
    public void containsElementInput1NegativeOutputTrue() {

        // Arrange
        final Object[] array = {-2_147_483_648};
        final Object element = -2_147_483_648;

        // Act
        final boolean actual = Objects.containsElement(array, element);

        // Assert result
        Assert.assertTrue(actual);
    }

    // Test written by Diffblue Cover.

    @Test
    public void containsElementInput1ZeroOutputFalse() {

        // Arrange
        final Object[] array = {null};
        final Object element = 0;

        // Act
        final boolean actual = Objects.containsElement(array, element);

        // Assert result
        Assert.assertFalse(actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void containsElementInputNullNullOutputFalse() {

        // Arrange
        final Object[] array = null;
        final Object element = null;

        // Act
        final boolean actual = Objects.containsElement(array, element);

        // Assert result
        Assert.assertFalse(actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void getDisplayStringInputNegativeOutputNotNull() {

        // Arrange
        final Object obj = -1000;

        // Act
        final String actual = Objects.getDisplayString(obj);

        // Assert result
        Assert.assertEquals("-1000", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void getDisplayStringInputNullOutputNotNull() {

        // Arrange
        final Object obj = null;

        // Act
        final String actual = Objects.getDisplayString(obj);

        // Assert result
        Assert.assertEquals("", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void hashCodeInputTrueOutputPositive() {

        // Arrange
        final boolean bool = true;

        // Act
        final int actual = Objects.hashCode(bool);

        // Assert result
        Assert.assertEquals(1231, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void hashCodeInputZeroOutputZero() {

        // Arrange
        final double dbl = 0.0;

        // Act
        final int actual = Objects.hashCode(dbl);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void hashCodeInputZeroOutputZero2() {

        // Arrange
        final float flt = 0.0f;

        // Act
        final int actual = Objects.hashCode(flt);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void identityToStringInputNullOutputNotNull() {

        // Arrange
        final Object obj = null;

        // Act
        final String actual = Objects.identityToString(obj);

        // Assert result
        Assert.assertEquals("", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void isArrayInputNullOutputFalse() {

        // Arrange
        final Object obj = null;

        // Act
        final boolean actual = Objects.isArray(obj);

        // Assert result
        Assert.assertFalse(actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void isArrayInputZeroOutputFalse() {

        // Arrange
        final Object obj = 0;

        // Act
        final boolean actual = Objects.isArray(obj);

        // Assert result
        Assert.assertFalse(actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void isCheckedExceptionInputNullOutputTrue() {

        // Arrange
        final Throwable ex = null;

        // Act
        final boolean actual = Objects.isCheckedException(ex);

        // Assert result
        Assert.assertTrue(actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void isCompatibleWithThrowsClauseInputNull0OutputFalse() {

        // Arrange
        final Throwable ex = null;
        final Class[] declaredExceptions = {};

        // Act
        final boolean actual = Objects.isCompatibleWithThrowsClause(ex, declaredExceptions);

        // Assert result
        Assert.assertFalse(actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void isCompatibleWithThrowsClauseInputNullNullOutputFalse() {

        // Arrange
        final Throwable ex = null;
        final Class[] declaredExceptions = null;

        // Act
        final boolean actual = Objects.isCompatibleWithThrowsClause(ex, declaredExceptions);

        // Assert result
        Assert.assertFalse(actual);
    }

    // Test written by Diffblue Cover.

    @Test
    public void isEmptyInput0OutputTrue() {

        // Arrange
        final Object[] array = {};

        // Act
        final boolean actual = Objects.isEmpty(array);

        // Assert result
        Assert.assertTrue(actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void isEmptyInput1OutputFalse() {

        // Arrange
        final byte[] array = {(byte)0};

        // Act
        final boolean actual = Objects.isEmpty(array);

        // Assert result
        Assert.assertFalse(actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void isEmptyInputNullOutputTrue() {

        // Arrange
        final Object[] array = null;

        // Act
        final boolean actual = Objects.isEmpty(array);

        // Assert result
        Assert.assertTrue(actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void isEmptyInputNullOutputTrue2() {

        // Arrange
        final byte[] array = null;

        // Act
        final boolean actual = Objects.isEmpty(array);

        // Assert result
        Assert.assertTrue(actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeClassNameInputNullOutputNotNull() {

        // Arrange
        final Object obj = null;

        // Act
        final String actual = Objects.nullSafeClassName(obj);

        // Assert result
        Assert.assertEquals("null", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeClassNameInputZeroOutputNotNull() {

        // Arrange
        final Object obj = 0;

        // Act
        final String actual = Objects.nullSafeClassName(obj);

        // Assert result
        Assert.assertEquals("java.lang.Integer", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeEqualsInputNullNullOutputTrue() {

        // Arrange
        final Object o1 = null;
        final Object o2 = null;

        // Act
        final boolean actual = Objects.nullSafeEquals(o1, o2);

        // Assert result
        Assert.assertTrue(actual);
    }

    // Test written by Diffblue Cover.

    @Test
    public void nullSafeHashCodeInput0OutputPositive() {

        // Arrange
        final Object[] array = {};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(7, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput0OutputPositive2() {

        // Arrange
        final byte[] array = {};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(7, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput0OutputPositive3() {

        // Arrange
        final boolean[] array = {};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(7, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput0OutputPositive4() {

        // Arrange
        final char[] array = {};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(7, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput0OutputPositive5() {

        // Arrange
        final double[] array = {};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(7, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput0OutputPositive6() {

        // Arrange
        final float[] array = {};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(7, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput0OutputPositive7() {

        // Arrange
        final int[] array = {};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(7, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput0OutputPositive8() {

        // Arrange
        final long[] array = {};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(7, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput0OutputPositive9() {

        // Arrange
        final short[] array = {};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(7, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput1OutputNegative() {

        // Arrange
        final float[] array = {0x1p-149f /* 1.4013e-45 */};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(-2_143_289_341, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput1OutputPositive() {

        // Arrange
        final byte[] array = {(byte)-122};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(95, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput1OutputPositive2() {

        // Arrange
        final boolean[] array = {false};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(1454, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput1OutputPositive3() {

        // Arrange
        final char[] array = {'\u0000'};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(217, actual);
    }

    // Test written by Diffblue Cover.

    @Test
    public void nullSafeHashCodeInput1OutputPositive4() {

        // Arrange
        final Object[] array = {null};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(217, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput1OutputPositive5() {

        // Arrange
        final boolean[] array = {true};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(1448, actual);
    }

    // Test written by Diffblue Cover.

    @Test
    public void nullSafeHashCodeInput1OutputZero() {

        // Arrange
        final Object[] array = {-217};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput1OutputZero2() {

        // Arrange
        final double[] array = {0x0};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput1OutputZero3() {

        // Arrange
        final int[] array = {-217};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput1OutputZero4() {

        // Arrange
        final long[] array = {4_294_967_079L};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInput1OutputZero5() {

        // Arrange
        final short[] array = {(short)-217};

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInputNullOutputZero() {

        // Arrange
        final Object[] array = null;

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInputNullOutputZero2() {

        // Arrange
        final boolean[] array = null;

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInputNullOutputZero3() {

        // Arrange
        final byte[] array = null;

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInputNullOutputZero4() {

        // Arrange
        final char[] array = null;

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInputNullOutputZero5() {

        // Arrange
        final double[] array = null;

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInputNullOutputZero6() {

        // Arrange
        final float[] array = null;

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInputNullOutputZero7() {

        // Arrange
        final int[] array = null;

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInputNullOutputZero8() {

        // Arrange
        final long[] array = null;

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInputNullOutputZero9() {

        // Arrange
        final short[] array = null;

        // Act
        final int actual = Objects.nullSafeHashCode(array);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeHashCodeInputNullOutputZero10() {

        // Arrange
        final Object obj = null;

        // Act
        final int actual = Objects.nullSafeHashCode(obj);

        // Assert result
        Assert.assertEquals(0, actual);
    }

    // Test written by Diffblue Cover.

    @Test
    public void nullSafeToStringInput0OutputNotNull() {

        // Arrange
        final Object[] array = {};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput0OutputNotNull2() {

        // Arrange
        final boolean[] array = {};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput0OutputNotNull3() {

        // Arrange
        final byte[] array = {};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput0OutputNotNull4() {

        // Arrange
        final char[] array = {};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput0OutputNotNull5() {

        // Arrange
        final int[] array = {};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput0OutputNotNull6() {

        // Arrange
        final long[] array = {};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput0OutputNotNull7() {

        // Arrange
        final short[] array = {};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput0OutputNotNull8() {

        // Arrange
        final double[] array = {};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput0OutputNotNull9() {

        // Arrange
        final float[] array = {};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{}", actual);
    }

    // Test written by Diffblue Cover.

    @Test
    public void nullSafeToStringInput1OutputNotNull() {

        // Arrange
        final Object[] array = {null};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{,}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput1OutputNotNull2() {

        // Arrange
        final boolean[] array = {true};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{true}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput1OutputNotNull3() {

        // Arrange
        final byte[] array = {(byte)-5};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{-5}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput1OutputNotNull4() {

        // Arrange
        final char[] array = {'\u0001'};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{\'\u0001\'}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput1OutputNotNull5() {

        // Arrange
        final int[] array = {-5};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{-5}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput1OutputNotNull6() {

        // Arrange
        final short[] array = {(short)-5};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{-5}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput1OutputNotNull7() {

        // Arrange
        final long[] array = {1L};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{1}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput1OutputNotNull8() {

        // Arrange
        final float[] array = {Float.NaN};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{NaN}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInput1OutputNotNull9() {

        // Arrange
        final double[] array = {Double.NEGATIVE_INFINITY};

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("{-Infinity}", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInputNullOutputNotNull() {

        // Arrange
        final Object[] array = null;

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("null", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInputNullOutputNotNull2() {

        // Arrange
        final boolean[] array = null;

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("null", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInputNullOutputNotNull3() {

        // Arrange
        final byte[] array = null;

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("null", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInputNullOutputNotNull4() {

        // Arrange
        final char[] array = null;

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("null", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInputNullOutputNotNull5() {

        // Arrange
        final int[] array = null;

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("null", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInputNullOutputNotNull6() {

        // Arrange
        final long[] array = null;

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("null", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInputNullOutputNotNull7() {

        // Arrange
        final short[] array = null;

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("null", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInputNullOutputNotNull8() {

        // Arrange
        final float[] array = null;

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("null", actual);
    }

    // Test written by Diffblue Cover.
    @Test
    public void nullSafeToStringInputNullOutputNotNull9() {

        // Arrange
        final double[] array = null;

        // Act
        final String actual = Objects.nullSafeToString(array);

        // Assert result
        Assert.assertEquals("null", actual);
    }
}
