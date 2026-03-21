package com.reajason.javaweb.dubbo;

import org.apache.dubbo.config.spring.context.annotation.EnableDubbo;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableDubbo
public class VulDubbo315Application {

    public static void main(String[] args) {
        SpringApplication.run(VulDubbo315Application.class, args);
    }

}
