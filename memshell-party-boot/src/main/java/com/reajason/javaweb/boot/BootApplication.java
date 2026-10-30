package com.reajason.javaweb.boot;

import com.reajason.javaweb.memshell.PluginLoadResult;
import com.reajason.javaweb.memshell.PluginBootstrap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author ReaJason
 */
@SpringBootApplication
@Slf4j
public class BootApplication {

    public static void main(String[] args) {
        PluginLoadResult plugins = PluginBootstrap.load();
        if (!plugins.getPluginJars().isEmpty()) {
            log.info("Loaded {} plugin jar(s) from {}", plugins.getPluginJars().size(), plugins.getDirectory());
        }
        for (String warning : plugins.getWarnings()) {
            log.warn(warning);
        }
        SpringApplication.run(BootApplication.class, args);
    }
}