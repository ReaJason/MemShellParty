package com.reajason.javaweb.examples.customgui.packer;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import org.kohsuke.MetaInfServices;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

/**
 * 自定义 packer 的 SPI 入口：把注入器字节 gzip 压缩后做 URL-safe Base64（不带 padding），
 * 适合放在 URL 参数或 HTTP Header/Cookie 里传输 —— 标准 Base64 的 {@code + / =}
 * 在 URL 与 Header 里需要额外转义。
 *
 * <p>{@code @MetaInfServices} 生成
 * {@code META-INF/services/com.reajason.javaweb.packer.Packer}，
 * {@code PackerRegistry} 通过 ServiceLoader 发现它；{@code @PackerMeta.parent} 决定界面里的
 * 分组（这里挂在内置的 Base64 分组下，不要求存在同名 packer）。
 *
 * <p>打包器只处理后置的投递编码：生成器产出的注入器字节与内置 packer 完全一致，
 * 换 packer 不改变内存马本身，只改变「怎么把字节送到目标」。
 *
 * @author ReaJason
 */
@MetaInfServices(Packer.class)
// order：内置 packer 用 100 起的递增序号，第三方默认 10000 排在末尾
@PackerMeta(name = GzipBase64URLPacker.NAME, parent = Packers.Base64, order = 10000)
public class GzipBase64URLPacker implements Packer {

    /**
     * 注册名：GUI / REST / MCP 里的打包方式名称，也是 {@code ShellConfig} 之外的字符串参数值。
     * 自定义 packer 不在 {@code Packers} 常量类里，自己维护一个常量即可。
     */
    public static final String NAME = "GzipBase64URL";

    @Override
    public String pack(ClassPackerConfig config) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
                gzip.write(config.getClassBytes());
            }
            return Base64.getUrlEncoder().withoutPadding().encodeToString(out.toByteArray());
        } catch (IOException e) {
            throw new IllegalStateException("gzip compress failed", e);
        }
    }

    /**
     * 产物走 URL 参数 / Header / Cookie：生成结果会按 4KB 的 Header 预算给出体积预警。
     */
    @Override
    public boolean headerTransported() {
        return true;
    }
}
