package com.reajason.javaweb.boot.mcp;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.boot.service.ClassNameParseService;
import com.reajason.javaweb.boot.service.GenerationOutcome;
import com.reajason.javaweb.boot.service.MemShellGenerationService;
import com.reajason.javaweb.boot.service.ProbeContentConfigMapper;
import com.reajason.javaweb.boot.service.ProbeContentParams;
import com.reajason.javaweb.boot.service.ProbeGenerationService;
import com.reajason.javaweb.boot.service.ShellToolConfigMapper;
import com.reajason.javaweb.boot.service.ShellToolParams;
import com.reajason.javaweb.boot.service.SupportMatrixService;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * MemShellParty 的 MCP 工具面。
 * <p>
 * 三个工具构成「先查后生成」的闭环：{@code list_support_matrix} 是参数合法性的唯一来源，
 * 两个 generate 工具负责产出。载荷默认落盘，只回传路径与摘要——载荷本体常有数十 KB，
 * 内联进模型上下文既无用又昂贵，故需显式用 {@code output} 索取。
 *
 * @author ReaJason
 */
public class MemShellMcpTools {

    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private static final String DEFAULT_PACKER = "Base64";
    private static final String DEFAULT_OUTPUT = "metadata";
    private static final int DEFAULT_SECONDS = 5;

    private final MemShellGenerationService memShellGenerationService;
    private final ProbeGenerationService probeGenerationService;
    private final SupportMatrixService supportMatrixService;
    private final ClassNameParseService classNameParseService;
    private final McpPayloadWriter payloadWriter;

    public MemShellMcpTools(MemShellGenerationService memShellGenerationService,
                            ProbeGenerationService probeGenerationService,
                            SupportMatrixService supportMatrixService,
                            ClassNameParseService classNameParseService,
                            McpPayloadWriter payloadWriter) {
        this.memShellGenerationService = memShellGenerationService;
        this.probeGenerationService = probeGenerationService;
        this.supportMatrixService = supportMatrixService;
        this.classNameParseService = classNameParseService;
        this.payloadWriter = payloadWriter;
    }

    @McpTool(name = "list_support_matrix",
            description = """
                    Returns the MemShellParty capability matrix. Always call this before generating:
                    it is the only authoritative source of valid server / shellTool / shellType
                    combinations and packer names. Combos not listed here will fail generation.""")
    public SupportMatrixPayload listSupportMatrix() {
        return new SupportMatrixPayload(
                supportMatrixService.config(),
                supportMatrixService.packerTree(),
                supportMatrixService.commandConfigs(),
                supportMatrixService.probeResponseBodyServers(),
                Arrays.stream(ProbeMethod.values()).map(Enum::name).toList(),
                Arrays.stream(ProbeContent.values()).map(Enum::name).toList(),
                supportMatrixService.probeContentsByMethod());
    }

    @McpTool(name = "parse_class_name",
            description = """
                    Extracts the fully qualified class name from Java class bytes.

                    Needed to complete the Custom shell workflow: shellTool="Custom" requires both
                    shellClassBase64 and shellClassName, and callers normally only hold the compiled
                    bytes. Parse first, then pass the returned name as shellClassName.""")
    public ClassNamePayload parseClassName(
            @McpToolParam(description = "Base64-encoded .class file bytes.", required = true)
            String shellClassBase64) {
        return new ClassNamePayload(classNameParseService.parse(shellClassBase64));
    }

    @McpTool(name = "generate_memshell",
            description = """
                    Generates a Java memory shell payload. Call list_support_matrix first and use a
                    server / shellTool / shellType triple listed there.

                    Only the parameters relevant to the chosen shellTool are consumed; the rest are
                    ignored. `pass` is shared by Godzilla, Behinder and AntSword. `key` applies to
                    Godzilla only. `paramName` / `template` / `encryptor` / `implementationClass`
                    apply to Command only. Use `encryptor` and `implementationClass` values from
                    list_support_matrix.commandConfigs.

                    The payload is written to a file and the response carries the path and SHA-256.
                    Pass output="base64" or "both" to also get the payload content inline.""")
    public GenerationResultPayload generateMemShell(
            @McpToolParam(description = "Target server, e.g. Tomcat. Must be a key of list_support_matrix.servers.",
                    required = true) String server,
            @McpToolParam(description = "Shell tool / feature, e.g. Godzilla. Must be listed under the chosen server.",
                    required = true) String shellTool,
            @McpToolParam(description = "Shell type, e.g. Filter. Must be listed under the chosen server and shellTool.",
                    required = true) String shellType,
            @McpToolParam(description = "Target server version, e.g. 9.0.80. Used to pick version-specific bytecode.",
                    required = false) String serverVersion,
            @McpToolParam(description = "Target JRE class file version, e.g. 50 for Java 6, 52 for Java 8, 61 for Java 17. Defaults to 50.",
                    required = false) Integer targetJreVersion,
            @McpToolParam(description = "Remove Java module restrictions. Automatically enabled when targetJreVersion >= 53.",
                    required = false) Boolean byPassJavaModule,
            @McpToolParam(description = "Add debug logging to the generated payload.", required = false) Boolean debug,
            @McpToolParam(description = "Shrink the bytecode to reduce payload size.", required = false) Boolean shrink,
            @McpToolParam(description = "Append a lambda-style suffix to generated class names.", required = false) Boolean lambdaSuffix,
            @McpToolParam(description = "Wrap the injector in a ResponseBody probe so injection returns the result inline.",
                    required = false) Boolean probe,
            @McpToolParam(description = "Convert Java EE class names to Jakarta EE.", required = false) Boolean jakarta,
            @McpToolParam(description = "Fully qualified shell class name. Auto-generated when omitted.",
                    required = false) String shellClassName,
            @McpToolParam(description = "Shared password for Godzilla / Behinder / AntSword.", required = false) String pass,
            @McpToolParam(description = "Godzilla encryption key.", required = false) String key,
            @McpToolParam(description = "HTTP header name the shell expects for authentication.", required = false) String headerName,
            @McpToolParam(description = "HTTP header value the shell expects for authentication.", required = false) String headerValue,
            @McpToolParam(description = "Command shell: request parameter name carrying the command.", required = false) String paramName,
            @McpToolParam(description = "Command shell: command template, using {command} as placeholder.", required = false) String template,
            @McpToolParam(description = "Command shell: encryptor name from list_support_matrix.commandConfigs.encryptors.",
                    required = false) String encryptor,
            @McpToolParam(description = "Command shell: implementation class from list_support_matrix.commandConfigs.implementationClasses.",
                    required = false) String implementationClass,
            @McpToolParam(description = "Custom shell: base64 of the custom class. Required when shellTool is Custom.",
                    required = false) String shellClassBase64,
            @McpToolParam(description = "Injector URL pattern. Defaults to /*.", required = false) String urlPattern,
            @McpToolParam(description = "Injector class name. Auto-generated when omitted.", required = false) String injectorClassName,
            @McpToolParam(description = "Initialise via a static code block calling the constructor. Required by some Agent shell types.",
                    required = false) Boolean staticInitialize,
            @McpToolParam(description = "Packer name from list_support_matrix.packers. Defaults to Base64.",
                    required = false) String packer,
            @McpToolParam(description = "metadata (default, file only), base64 (inline only), or both.",
                    required = false) String output,
            @McpToolParam(description = "Output file name, base name only; directories are ignored.", required = false) String filename) {

        List<String> warnings = new ArrayList<>();
        OutputMode outputMode = OutputMode.parse(output, warnings);
        Packers resolvedPacker = resolvePacker(packer, warnings);

        ShellConfig shellConfig = buildShellConfig(server, serverVersion, shellTool, shellType,
                targetJreVersion, byPassJavaModule, debug, shrink, lambdaSuffix, probe, jakarta);

        InjectorConfig injectorConfig = InjectorConfig.builder()
                .urlPattern(urlPattern == null ? "/*" : urlPattern)
                .injectorClassName(injectorClassName)
                .staticInitialize(isTrue(staticInitialize))
                .build();

        GenerationOutcome<MemShellResult> outcome = generate(
                shellConfig, injectorConfig, shellToolParams(shellClassName, pass, key, headerName,
                        headerValue, paramName, template, encryptor, implementationClass, shellClassBase64),
                resolvedPacker);

        MemShellResult result = outcome.result();
        String baseName = filesBaseName(filename,
                orDefault(server, "server") + "-" + orDefault(shellTool, "tool")
                        + "-" + orDefault(shellType, "type"));
        List<WrittenFile> files = write(baseName, outputMode, outcome,
                isJar(resolvedPacker) ? "jar" : "txt");

        return new GenerationResultPayload(
                "memshell",
                result.getShellClassName(),
                result.getShellSize(),
                result.getInjectorClassName(),
                result.getInjectorSize(),
                resolvedPacker.name(),
                files,
                inlineContent(outputMode, outcome),
                inlineContents(outputMode, outcome),
                warnings);
    }

    @McpTool(name = "generate_probe",
            description = """
                    Generates a probe payload used to confirm code execution on a target before
                    deploying a full memory shell.

                    probeMethod selects the technique:
                      - DNSLog: payload triggers a DNS lookup to `host`. Requires host.
                      - Sleep: payload sleeps `seconds` on each matching request. Requires server.
                      - ResponseBody: payload returns command output in the response body.
                        Requires server, and optionally reqParamName and commandTemplate.

                    Note there is no shellType parameter for probes: the server value alone selects
                    the injection point. For ResponseBody, use a value from
                    list_support_matrix.probeResponseBodyServers.

                    The supported probeContent values differ per probeMethod; consult
                    list_support_matrix.probeContentsByMethod rather than guessing.

                    The payload is written to a file and the response carries the path and SHA-256.
                    Pass output="base64" or "both" to also get the payload content inline.""")
    public GenerationResultPayload generateProbe(
            @McpToolParam(description = "One of list_support_matrix.probeMethods: DNSLog, Sleep or ResponseBody.",
                    required = true) String probeMethod,
            @McpToolParam(description = "Target server for Sleep and ResponseBody probes, e.g. Tomcat.",
                    required = false) String server,
            @McpToolParam(description = "DNSLog callback host. Required when probeMethod is DNSLog.",
                    required = false) String host,
            @McpToolParam(description = "Sleep duration in seconds. Defaults to 5.", required = false) Integer seconds,
            @McpToolParam(description = "ResponseBody: request parameter name carrying the command. Auto-generated when omitted.",
                    required = false) String reqParamName,
            @McpToolParam(description = "ResponseBody: command template using {command} as placeholder.",
                    required = false) String commandTemplate,
            @McpToolParam(description = "What the probe should detect. Valid values differ per probeMethod — see "
                    + "list_support_matrix.probeContentsByMethod. Defaults to Server for DNSLog and Sleep, Command for ResponseBody.",
                    required = false) String probeContent,
            @McpToolParam(description = "Fully qualified probe class name. Auto-generated when omitted.",
                    required = false) String shellClassName,
            @McpToolParam(description = "Target JRE class file version, e.g. 50 for Java 6, 52 for Java 8. Defaults to 50.",
                    required = false) Integer targetJreVersion,
            @McpToolParam(description = "Remove Java module restrictions. Automatically enabled when targetJreVersion >= 53.",
                    required = false) Boolean byPassJavaModule,
            @McpToolParam(description = "Add debug logging to the generated payload.", required = false) Boolean debug,
            @McpToolParam(description = "Shrink the bytecode to reduce payload size.", required = false) Boolean shrink,
            @McpToolParam(description = "Initialise via a static code block calling the constructor.",
                    required = false) Boolean staticInitialize,
            @McpToolParam(description = "Append a lambda-style suffix to generated class names.", required = false) Boolean lambdaSuffix,
            @McpToolParam(description = "Packer name from list_support_matrix.packers. Defaults to Base64.",
                    required = false) String packer,
            @McpToolParam(description = "metadata (default, file only), base64 (inline only), or both.",
                    required = false) String output,
            @McpToolParam(description = "Output file name, base name only; directories are ignored.", required = false) String filename) {

        List<String> warnings = new ArrayList<>();
        OutputMode outputMode = OutputMode.parse(output, warnings);
        Packers resolvedPacker = resolvePacker(packer, warnings);
        ProbeMethod resolvedMethod = resolveProbeMethod(probeMethod);
        ProbeContent resolvedContent = resolveProbeContent(resolvedMethod, probeContent, warnings);

        ProbeConfig.ProbeConfigBuilder probeConfigBuilder = ProbeConfig.builder()
                .probeMethod(resolvedMethod)
                .probeContent(resolvedContent)
                .byPassJavaModule(isTrue(byPassJavaModule))
                .debug(isTrue(debug))
                .shrink(isTrue(shrink))
                .staticInitialize(isTrue(staticInitialize))
                .lambdaSuffix(isTrue(lambdaSuffix));
        // 仅在显式提供时覆盖，否则会顶掉 @Builder.Default 自动生成的类名
        if (shellClassName != null && !shellClassName.isBlank()) {
            probeConfigBuilder.shellClassName(shellClassName);
        }
        if (targetJreVersion != null) {
            probeConfigBuilder.targetJreVersion(targetJreVersion);
        }
        ProbeConfig probeConfig = probeConfigBuilder.build();

        ProbeContentParams probeContentParams = new ProbeContentParams(
                host,
                orDefault(seconds, DEFAULT_SECONDS),
                server,
                server,
                reqParamName,
                commandTemplate);

        String baseName = filesBaseName(filename,
                "probe-" + resolvedMethod.name() + "-" + orDefault(host, orDefault(server, "target")));

        GenerationOutcome<ProbeShellResult> outcome = probeGenerationService.generate(
                probeConfig,
                ProbeContentConfigMapper.map(resolvedMethod, probeContentParams),
                resolvedPacker);

        return new GenerationResultPayload(
                "probe",
                outcome.result().getShellClassName(),
                outcome.result().getShellSize(),
                null,
                0L,
                resolvedPacker.name(),
                write(baseName, outputMode, outcome, "txt"),
                inlineContent(outputMode, outcome),
                inlineContents(outputMode, outcome),
                warnings);
    }

    private GenerationOutcome<MemShellResult> generate(ShellConfig shellConfig,
                                                       InjectorConfig injectorConfig,
                                                       ShellToolParams shellToolParams,
                                                       Packers packer) {
        try {
            return memShellGenerationService.generate(shellConfig, injectorConfig,
                    ShellToolConfigMapper.map(shellConfig.getShellTool(), shellToolParams), packer);
        } catch (GenerationException | IllegalArgumentException e) {
            // ServerFactory 对未知 server 抛 IllegalArgumentException，其余路径抛 GenerationException
            throw new GenerationException(e.getMessage()
                    + " — call list_support_matrix and retry with a combination listed there.", e);
        }
    }

    private static ShellToolParams shellToolParams(String shellClassName, String pass, String key,
                                                   String headerName, String headerValue, String paramName,
                                                   String template, String encryptor,
                                                   String implementationClass, String shellClassBase64) {
        // pass 在 REST 契约中是三个独立字段，MCP 只暴露一个；只有对应 shellTool 消费它，故同值填充安全
        return new ShellToolParams(shellClassName, pass, key, paramName, template, pass, pass,
                headerName, headerValue, shellClassBase64, encryptor, implementationClass);
    }

    private static ShellConfig buildShellConfig(String server, String serverVersion, String shellTool,
                                                String shellType, Integer targetJreVersion,
                                                Boolean byPassJavaModule, Boolean debug, Boolean shrink,
                                                Boolean lambdaSuffix, Boolean probe, Boolean jakarta) {
        ShellConfig.ShellConfigBuilder builder = ShellConfig.builder()
                .server(server)
                .shellTool(shellTool)
                .shellType(shellType)
                .byPassJavaModule(isTrue(byPassJavaModule))
                .debug(isTrue(debug))
                .shrink(isTrue(shrink))
                .lambdaSuffix(isTrue(lambdaSuffix))
                .probe(isTrue(probe))
                .jakarta(isTrue(jakarta));
        if (serverVersion != null) {
            builder.serverVersion(serverVersion);
        }
        if (targetJreVersion != null) {
            builder.targetJreVersion(targetJreVersion);
        }
        return builder.build();
    }

    private List<WrittenFile> write(String baseName, OutputMode outputMode,
                                    GenerationOutcome<?> outcome, String singleExtension) {
        if (outputMode == OutputMode.BASE64) {
            return List.of();
        }
        try {
            Map<String, String> allPackResults = outcome.allPackResults();
            if (allPackResults != null) {
                return payloadWriter.writeAggregate(baseName, allPackResults);
            }
            return List.of(payloadWriter.writeSingle(baseName, singleExtension, outcome.packResult()));
        } catch (IOException e) {
            // MCP 工具方法不声明受检异常，包装为未受检并保留可读原因
            throw new UncheckedIOException(
                    "failed to write payload into " + payloadWriter.outputDir()
                            + " (check MEMSHELL_MCP_OUTPUT_DIR and its write permission)", e);
        }
    }

    /**
     * 单打包器产出的内联正文；聚合打包器走 {@link #inlineContents}。
     */
    private static String inlineContent(OutputMode outputMode, GenerationOutcome<?> outcome) {
        if (outputMode == OutputMode.METADATA || outcome.allPackResults() != null) {
            return null;
        }
        return outcome.packResult();
    }

    /**
     * 聚合打包器产出的内联正文。聚合结果无法压进单个字符串，故以打包器名为键。
     */
    private static Map<String, String> inlineContents(OutputMode outputMode, GenerationOutcome<?> outcome) {
        if (outputMode == OutputMode.METADATA || outcome.allPackResults() == null) {
            return null;
        }
        return outcome.allPackResults();
    }

    private static String filesBaseName(String filename, String fallback) {
        if (filename != null && !filename.isBlank()) {
            return filename;
        }
        return LocalDateTime.now().format(TIMESTAMP) + "-" + fallback;
    }

    private static boolean isJar(Packers packer) {
        return packer.getInstance() instanceof JarPacker;
    }

    private static Packers resolvePacker(String packer, List<String> warnings) {
        if (packer == null || packer.isBlank()) {
            return Packers.valueOf(DEFAULT_PACKER);
        }
        try {
            return Packers.valueOf(packer);
        } catch (IllegalArgumentException e) {
            warnings.add("unknown packer '" + packer + "', fell back to " + DEFAULT_PACKER
                    + "; call list_support_matrix to see valid names");
            return Packers.valueOf(DEFAULT_PACKER);
        }
    }

    private static ProbeMethod resolveProbeMethod(String probeMethod) {
        try {
            return ProbeMethod.valueOf(probeMethod);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new GenerationException("unknown probeMethod '" + probeMethod + "', expected one of "
                    + Arrays.toString(ProbeMethod.values()) + " — call list_support_matrix first");
        }
    }

    private static ProbeContent resolveProbeContent(ProbeMethod method, String probeContent,
                                                    List<String> warnings) {
        ProbeContent fallback = defaultProbeContent(method);
        if (probeContent == null || probeContent.isBlank()) {
            return fallback;
        }
        try {
            return ProbeContent.valueOf(probeContent);
        } catch (IllegalArgumentException e) {
            warnings.add("unknown probeContent '" + probeContent + "', fell back to " + fallback.name());
            return fallback;
        }
    }

    /**
     * 各探测方式支持的 probeContent 不同，不存在通用默认值，故按方式分叉。
     * 合法子集见 {@code list_support_matrix.probeContentsByMethod}。
     */
    private static ProbeContent defaultProbeContent(ProbeMethod method) {
        return switch (method) {
            case DNSLog, Sleep -> ProbeContent.Server;
            case ResponseBody -> ProbeContent.Command;
        };
    }

    private static <T> T orDefault(T value, T fallback) {
        return value == null ? fallback : value;
    }

    private static boolean isTrue(Boolean value) {
        return Boolean.TRUE.equals(value);
    }

    private enum OutputMode {
        METADATA, BASE64, BOTH;

        static OutputMode parse(String raw, List<String> warnings) {
            if (raw == null || raw.isBlank()) {
                return METADATA;
            }
            for (OutputMode mode : values()) {
                if (mode.name().equalsIgnoreCase(raw)) {
                    return mode;
                }
            }
            warnings.add("unknown output '" + raw + "', fell back to metadata");
            return METADATA;
        }
    }
}
