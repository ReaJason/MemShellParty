package com.reajason.javaweb.packer;

import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.memshell.config.ObfuscationConfig;

/** 单次生成/转换的 Packer 约束，所有服务端入口共用。 */
public final class PackerConstraints {
    private final String packerName;
    private final Packer packer;

    PackerConstraints(String packerName, Packer packer) {
        this.packerName = packerName;
        this.packer = packer;
    }

    public static PackerConstraints forPacker(String packerName) {
        String normalized = packerName == null ? PackerRegistry.RAW : packerName.trim();
        Packer packer = normalized.isEmpty() ? null : PackerRegistry.getInstance().get(normalized);
        return new PackerConstraints(normalized, packer);
    }

    public String getPackerName() {
        return packerName;
    }

    /** SpringGzipJDK17 系必须在生成前固定到要求的包，否则 cglib 定义类时才失败。 */
    public String enforceClassName(String className) {
        if (packer != null && packer.requiresSpringExpressionPackage()
                && !PackerSupport.isSpringExpressionClassName(className)) {
            return packer.generateSpringExpressionClassName();
        }
        return className;
    }

    /** SpEL 的 10000 字符限制必须在混淆前处理，打包失败后无法补救。 */
    public void constrainObfuscation(ObfuscationConfig obfuscation) {
        if (obfuscation == null || !obfuscation.isEnabled()
                || packer == null || !packer.transportedAsSpelExpression()) {
            return;
        }
        obfuscation.setEnabled(false);
    }
}
