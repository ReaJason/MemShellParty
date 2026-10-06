package com.reajason.javaweb.boot.config;

import com.reajason.javaweb.boot.mcp.McpPayloadWriter;
import com.reajason.javaweb.boot.mcp.MemShellMcpTools;
import com.reajason.javaweb.boot.service.MemShellGenerationService;
import com.reajason.javaweb.boot.service.ProbeGenerationService;
import com.reajason.javaweb.boot.service.SupportMatrixService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Paths;

/**
 * MCP 工具与访问控制的装配。
 * <p>
 * 整体受 {@code spring.ai.mcp.server.enabled} 门控，默认关闭，故对既有 REST 部署零影响。
 * 开启后 Spring AI 的 BeanPostProcessor 会扫描 {@link MemShellMcpTools} 上的
 * {@code @McpTool} 方法并注册为 MCP 工具。
 *
 * @author ReaJason
 */
@Configuration
@ConditionalOnProperty(prefix = "spring.ai.mcp.server", name = "enabled", havingValue = "true")
public class McpConfiguration {

    @Bean
    public McpPayloadWriter mcpPayloadWriter(
            @Value("${memshell.mcp.output-dir:./memshell-output}") String outputDir) throws IOException {
        return new McpPayloadWriter(Paths.get(outputDir));
    }

    @Bean
    public MemShellMcpTools memShellMcpTools(MemShellGenerationService memShellGenerationService,
                                             ProbeGenerationService probeGenerationService,
                                             SupportMatrixService supportMatrixService,
                                             McpPayloadWriter mcpPayloadWriter) {
        return new MemShellMcpTools(memShellGenerationService, probeGenerationService,
                supportMatrixService, mcpPayloadWriter);
    }

    @Bean
    public FilterRegistrationBean<McpAccessFilter> mcpAccessFilter(
            @Value("${spring.ai.mcp.server.streamable-http.mcp-endpoint:/mcp}") String mcpEndpoint,
            @Value("${memshell.mcp.token:}") String token) {
        FilterRegistrationBean<McpAccessFilter> registration =
                new FilterRegistrationBean<>(new McpAccessFilter(mcpEndpoint, token));
        registration.addUrlPatterns(mcpEndpoint);
        registration.setOrder(0);
        return registration;
    }
}
