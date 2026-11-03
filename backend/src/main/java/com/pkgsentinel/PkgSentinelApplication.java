package com.pkgsentinel;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class PkgSentinelApplication {

    public static void main(String[] args) {
        SpringApplication.run(PkgSentinelApplication.class, args);
    }
}

