package com.reajason.javaweb.boot.mcp;

import com.reajason.javaweb.boot.dto.MemShellGenerateRequest;
import com.reajason.javaweb.boot.dto.MemShellGenerateResponse;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateRequest;
import com.reajason.javaweb.boot.dto.ProbeShellGenerateResponse;
import com.reajason.javaweb.boot.service.GenerationService;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.ToolConfigFactory;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.generator.response.ResponseGenerator;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
    private final MemShellGenerator memShellGenerator;

    public MemShellMcpTools(GenerationService generationService, MemShellGenerator memShellGenerator) {
        this.generationService = generationService;
        this.memShellGenerator = memShellGenerator;
    }

    @McpTool(name = "memshell_capabilities", description = """
            List everything this server can generate: supported target servers mapped to their shell tools \
            and shell (injector) types, every shell tool's configurable parameters (name, type, enum options, \
            basic/advanced group), available payload packers, probe methods/contents and probe ResponseBody/ResponseHeader servers. \
            Always call this first to discover valid values before calling generate_memshell or generate_probe_shell.""")
    public Map<String, Object> capabilities() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("servers", memShellGenerator.getShellTypeCatalog().asMap());
        result.put("shellToolConfigs", ToolConfigFactory.describeAll());
        result.put("packers", Packers.getPackerTree());
        result.put("probeMethods", Arrays.stream(ProbeMethod.values()).map(Enum::name).toList());
        result.put("probeContents", Arrays.stream(ProbeContent.values()).map(Enum::name).toList());
        result.put("probeResponseServers", ResponseGenerator.getSupportedServers());
        return result;
    }

    @McpTool(name = "generate_memshell", description = """
            Generate a Java memory shell (内存马): a fileless webshell injected into a running Java web server, \
            for authorized penetration testing. The request argument mirrors the REST API POST /api/memshell/generate: \
            {"shellConfig": {"server": "Tomcat", "shellTool": "Godzilla", "shellType": "Filter", "targetJreVersion": 50, \
            "shrink": true, "debug": false}, "injectorConfig": {"urlPattern": "/*"}, "shellToolConfig": {...}, "packer": "Base64"}. \
            server/shellTool/shellType must come from memshell_capabilities (e.g. server=Tomcat, shellTool=Godzilla, shellType=Filter). \
            shellToolConfig keys are the config field names listed under shellToolConfigs in memshell_capabilities: \
            Godzilla -> pass + key; Behinder/AntSword -> pass; Command -> paramName (plus optional template with a {command} \
            placeholder, encryptor, implementationClass); Suo5/NeoreGeorg/Proxy -> optional headerName + headerValue; \
            Custom -> shellClassBase64. A key the chosen shellTool does not support is rejected. \
            All blank optional fields fall back to secure random defaults. \
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
            ResponseBody -> echo data in the HTTP response body, needs {"server": "Tomcat", "reqParamName": "cmd", \
            "commandTemplate": "optional template with a {command} placeholder"}; ResponseHeader -> echo data in HTTP \
            response headers only (strictly no body fallback), needs {"server": "Tomcat", "reqParamName": "cmd", \
            "respHeaderName": "X-Result"} (valid servers are listed as probeResponseServers in memshell_capabilities; \
            respHeaderName defaults to a random X- prefixed name; results up to 1500 chars that are header-safe \
            ASCII are plain text (CR/LF normalize to spaces), otherwise results are Base64 and split across \
            <name>, <name>-2, ... with <name>-E: b64 and <name>-C: chunkCount (<name>-T: 1 when truncated to 4 chunks). \
            probeContent selects what to echo (Server, OS, JDK, Command, BasicInfo, ...). Returns the probe class name, \
            base64-encoded class bytes and the packed payload string.""")
    public ProbeShellGenerateResponse generateProbeShell(
            @McpToolParam(required = true, description = "Probe (echo) shell generation request, same JSON structure as POST /api/probe/generate")
            ProbeShellGenerateRequest request) {
        return generationService.generateProbeShell(request);
    }
}
