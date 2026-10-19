public class CpoolConsumers {
    public int field;

    public static String constant() {
        return "kuna_cpool_token";
    }

    public static int length(int[] values) {
        return values.length;
    }

    public static Object[] array(int count) {
        return new Object[count];
    }

    public static int readField(CpoolConsumers object) {
        return object.field;
    }

    public static int callMethod(CpoolConsumers object, int value) {
        return object.method(value);
    }

    public int method(int value) {
        return value + field;
    }

    public static Object nil() {
        return null;
    }

    public static boolean isNil(Object value) {
        return value == null;
    }
}
