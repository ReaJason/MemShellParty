package com.reajason.javaweb.boot.service;

/**
 * 内存马功能（shellTool）相关的全部可选参数。
 * <p>
 * 不同 shellTool 只消费其中一部分字段，由 {@link ShellToolConfigMapper} 按 shellTool 分派。
 * 作为 REST DTO 与 MCP 工具入参之间的中立载体，使映射逻辑只有一份。
 *
 * @author ReaJason
 */
public record ShellToolParams(
        String shellClassName,
        String godzillaPass,
        String godzillaKey,
        String commandParamName,
        String commandTemplate,
        String behinderPass,
        String antSwordPass,
        String headerName,
        String headerValue,
        String shellClassBase64,
        String encryptor,
        String implementationClass) {
}
