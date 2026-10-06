package com.reajason.javaweb.boot.mcp;

import java.util.List;
import java.util.Map;

/**
 * 生成类 MCP 工具的统一返回值。
 * <p>
 * 刻意不回显 {@code shellToolConfig}：其中的 Godzilla {@code pass}/{@code key} 等属于凭据，
 * 回显会把密钥写进模型上下文与调用日志。
 * <p>
 * {@code content} 与 {@code contents} 对应单打包器与聚合打包器两种情形，
 * 二者只会有一个非空——聚合打包器（如默认的 Base64）会产出多份载荷，
 * 无法塞进单个字符串。
 *
 * @param kind              生成类别，{@code memshell} 或 {@code probe}
 * @param shellClassName    载荷类名
 * @param shellSize         载荷字节数
 * @param injectorClassName 注入器类名，探测马为 {@code null}
 * @param injectorSize      注入器字节数，探测马为 {@code 0}
 * @param packer            实际使用的打包器名
 * @param files             已落盘的文件元数据；{@code output=base64} 时为空
 * @param content           单打包器载荷正文，仅 {@code output=base64|both} 时非空
 * @param contents          聚合打包器载荷正文，键为打包器名，仅 {@code output=base64|both} 时非空
 * @param warnings          非致命提示，例如参数被忽略或取值非法而回落
 * @author ReaJason
 */
public record GenerationResultPayload(
        String kind,
        String shellClassName,
        long shellSize,
        String injectorClassName,
        long injectorSize,
        String packer,
        List<WrittenFile> files,
        String content,
        Map<String, String> contents,
        List<String> warnings) {
}
