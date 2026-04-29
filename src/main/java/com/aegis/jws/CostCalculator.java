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
        long total = r.totalMemory();
        long max = r.maxMemory();
        long free = r.freeMemory();
        long used = total - free;
        long ceiling = max > 0 ? max : total;
        if (ceiling <= 0) return 0.0;
        double rawPressure = used / (double) ceiling;
        // headroom-aware: if heap hasn't expanded close to max, weight pressure lower
        double heapExpansion = total / (double) ceiling;
        double weighted = rawPressure * Math.min(1.0, heapExpansion + 0.25);
        return Math.max(0.0, Math.min(1.0, weighted));
    }
}
