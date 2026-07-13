package com.aegis.lifecycle;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.function.LongSupplier;

/** Provides the nanos seam (D5). Production uses System.nanoTime; tests inject a fake. */
@Configuration
public class LifecycleConfig {

    @Bean
    public LongSupplier lifecycleNanos() {
        return System::nanoTime;
    }
}
