package com.reajason.javaweb.boot.config;

import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Spring AI 的 HTTP 传输默认暴露无鉴权端点，这个过滤器是唯一的访问控制层，
 * 因此逐条钉住判定分支。
 *
 * @author ReaJason
 */
class McpAccessFilterTest {

    private static final String MCP_PATH = "/mcp";
    private static final String TOKEN = "s3cret-token";

    @Test
    void allowsRequestWithValidBearerToken() throws Exception {
        McpAccessFilter filter = new McpAccessFilter(MCP_PATH, TOKEN);
        MockHttpServletRequest request = mcpRequest("203.0.113.10");
        request.addHeader("Authorization", "Bearer " + TOKEN);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertNotNull(chain.getRequest(), "filter should have forwarded the request");
        assertEquals(200, response.getStatus());
    }

    @Test
    void rejectsRequestWithWrongToken() throws Exception {
        MockHttpServletResponse response = assertRejected(TOKEN, "203.0.113.10", "Bearer wrong-token");

        assertEquals(401, response.getStatus());
    }

    @Test
    void rejectsRequestWithMissingToken() throws Exception {
        MockHttpServletResponse response = assertRejected(TOKEN, "203.0.113.10", null);

        assertEquals(401, response.getStatus());
    }

    @Test
    void rejectsRequestWithMalformedAuthorizationHeader() throws Exception {
        MockHttpServletResponse response = assertRejected(TOKEN, "203.0.113.10", TOKEN);

        assertEquals(401, response.getStatus());
    }

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.1", "::1", "::ffff:127.0.0.1", "10.1.2.3", "192.168.1.5", "172.16.0.1", "172.31.255.254"})
    void allowsLoopbackAndPrivateOriginsWhenNoTokenConfigured(String remoteAddr) throws Exception {
        McpAccessFilter filter = new McpAccessFilter(MCP_PATH, "");
        MockHttpServletRequest request = mcpRequest(remoteAddr);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertNotNull(chain.getRequest(), "expected " + remoteAddr + " to be allowed");
    }

    @ParameterizedTest
    @ValueSource(strings = {"203.0.113.10", "8.8.8.8", "172.32.0.1", "172.15.0.1", "11.0.0.1"})
    void rejectsPublicOriginsWhenNoTokenConfigured(String remoteAddr) throws Exception {
        MockHttpServletResponse response = assertRejected("", remoteAddr, null);

        assertEquals(403, response.getStatus());
    }

    @Test
    void missingTokenDoesNotBlockNonMcpPaths() throws Exception {
        McpAccessFilter filter = new McpAccessFilter(MCP_PATH, "");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/memshell/generate");
        request.setRemoteAddr("203.0.113.10");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertNotNull(chain.getRequest(), "existing REST endpoints must keep their previous behaviour");
    }

    @Test
    void blankTokenIsTreatedAsUnsetRatherThanMatchingEmptyBearer() throws Exception {
        MockHttpServletResponse response = assertRejected("   ", "203.0.113.10", "Bearer ");

        assertEquals(403, response.getStatus());
    }

    private static MockHttpServletResponse assertRejected(String token, String remoteAddr, String authorizationHeader)
            throws ServletException, IOException {
        McpAccessFilter filter = new McpAccessFilter(MCP_PATH, token);
        MockHttpServletRequest request = mcpRequest(remoteAddr);
        if (authorizationHeader != null) {
            request.addHeader("Authorization", authorizationHeader);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertNull(chain.getRequest(), "filter should NOT have forwarded the request");
        return response;
    }

    private static MockHttpServletRequest mcpRequest(String remoteAddr) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", MCP_PATH);
        request.setRequestURI(MCP_PATH);
        request.setRemoteAddr(remoteAddr);
        return request;
    }
}
