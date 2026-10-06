package com.reajason.javaweb.boot.mcp;

/**
 * 已落盘载荷文件的元数据。
 * <p>
 * MCP 工具默认只回传这些元数据而非载荷内容本身，避免大体积 Base64 污染模型上下文。
 *
 * @param path   绝对路径
 * @param sha256 内容的 SHA-256 十六进制摘要
 * @param bytes  内容字节数
 * @author ReaJason
 */
public record WrittenFile(String path, String sha256, long bytes) {
}
