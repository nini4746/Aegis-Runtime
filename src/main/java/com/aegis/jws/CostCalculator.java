package com.aegis.jws;

public final class CostCalculator {

    private CostCalculator() {}

    public static double compute(double avgVerifyMs, int tokenSizeBytes, double memoryPressure) {
        double tokenSizeKb = tokenSizeBytes / 1024.0;
        return avgVerifyMs * 3.0
                + tokenSizeKb * 1.0
                + memoryPressure * 100.0 * 2.0;
    }

    public static double currentMemoryPressure() {
        Runtime r = Runtime.getRuntime();
        long used = r.totalMemory() - r.freeMemory();
        long max = r.maxMemory();
        if (max <= 0) return 0.0;
        return Math.min(1.0, used / (double) max);
    }
}
