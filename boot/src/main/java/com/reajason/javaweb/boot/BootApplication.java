package com.reajason.javaweb.boot;

import com.reajason.javaweb.memshell.Server;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Arrays;

/**
 * @author ReaJason
 */
@SpringBootApplication
@Slf4j
public class BootApplication {

    public static void main(String[] args) {
        SpringApplication.run(BootApplication.class, args);
        Server[] values = Server.values();
        log.info("Supported servers: {}", Arrays.toString(values));
        log.info("For another server, you can open a issue in GitHub, https://github.com/ReaJason/MemShellParty/issues/new?template=%E8%AF%B7%E6%B1%82%E9%80%82%E9%85%8D.md");
    }
}