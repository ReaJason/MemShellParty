package com.reajason.javaweb.boot.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * 保护 MCP 端点的访问控制过滤器。
 * <p>
 * Spring AI 的 HTTP 传输默认暴露一个无鉴权的 JSON-RPC 端点，因此这里补上：
 * <ol>
 *   <li>配置了 token —— 校验 {@code Authorization: Bearer <token>}，用常量时间比较避免时序侧信道</li>
 *   <li>未配置 token —— 仅放行回环与私网来源（覆盖 Docker 端口映射的常见访问路径），
 *       其余来源拒绝。部署到公网前必须配置 token。</li>
 * </ol>
 * 仅作用于 MCP 端点，不影响既有 REST 行为。
 *
 * @author ReaJason
 */
public class McpAccessFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(McpAccessFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final String mcpPath;
    private final String token;

    public McpAccessFilter(String mcpPath, String token) {
        this.mcpPath = mcpPath;
        this.token = token;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!mcpPath.equals(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }

        if (token != null && !token.isBlank()) {
            if (!hasValidToken(request)) {
                log.warn("Rejected MCP request from {}: invalid or missing bearer token", request.getRemoteAddr());
                reject(response, HttpServletResponse.SC_UNAUTHORIZED, "invalid or missing bearer token");
                return;
            }
        } else if (!isTrustedNetworkOrigin(request.getRemoteAddr())) {
            log.warn("Rejected MCP request from {}: no token configured and origin is not loopback or private network. "
                    + "Set MEMSHELL_MCP_TOKEN before exposing this service.", request.getRemoteAddr());
            reject(response, HttpServletResponse.SC_FORBIDDEN, "remote access requires a configured token");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean hasValidToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return false;
        }
        byte[] expected = token.getBytes(StandardCharsets.UTF_8);
        byte[] actual = header.substring(BEARER_PREFIX.length()).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expected, actual);
    }

    /**
     * 回环地址，或 RFC1918 私网地址。
     * <p>
     * 私网放行是为了覆盖 Docker 部署下的常见场景：宿主经端口映射访问容器时，
     * 容器看到的来源是网桥网关地址而非 127.0.0.1。代价是同一私网内的其它主机也被放行，
     * 因此公网部署必须配置 token。
     */
    static boolean isTrustedNetworkOrigin(String remoteAddr) {
        if (remoteAddr == null || remoteAddr.isBlank()) {
            return false;
        }
        String address = remoteAddr;
        if (address.startsWith("::ffff:")) {
            address = address.substring("::ffff:".length());
        }
        if ("127.0.0.1".equals(address) || "::1".equals(address) || "0:0:0:0:0:0:0:1".equals(address)) {
            return true;
        }
        String[] parts = address.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        Integer first = parseSegment(parts[0]);
        Integer second = parseSegment(parts[1]);
        if (first == null || second == null) {
            return false;
        }
        if (first == 10) {
            return true;
        }
        if (first == 172 && second >= 16 && second <= 31) {
            return true;
        }
        return first == 192 && second == 168;
    }

    private static Integer parseSegment(String segment) {
        try {
            return Integer.parseInt(segment);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static void reject(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }
}
