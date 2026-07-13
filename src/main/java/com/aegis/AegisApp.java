package com.aegis;

import com.aegis.lifecycle.PolicyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties(PolicyProperties.class)
public class AegisApp {
    public static void main(String[] args) {
        SpringApplication.run(AegisApp.class, args);
    }
}
