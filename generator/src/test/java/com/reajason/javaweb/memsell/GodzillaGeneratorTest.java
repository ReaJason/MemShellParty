package com.reajason.javaweb.memsell;

import com.reajason.javaweb.memsell.tomcat.godzilla.GodzillaFilter;
import com.reajason.javaweb.memsell.tomcat.godzilla.GodzillaListener;
import com.reajason.javaweb.util.ClassUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/11/23
 */
class GodzillaGeneratorTest {

    GodzillaGenerator godzillaGenerator = new GodzillaGenerator();
    String pass = "pass";
    String key = "key";
    String headerName = "User-Agent";
    String headerValue = "test";

    @Test
    @Disabled("just for generate")
    void testGenerate() throws IOException {
        String className = "org.apache.utils.CommonFilter";
        byte[] bytes = godzillaGenerator.generate(GodzillaFilter.class, className, pass, key, headerName, headerValue);
        IOUtils.write(bytes, Files.newOutputStream(Paths.get("CommonFilter.class")));
    }
}