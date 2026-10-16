package com.reajason.javaweb.memshell.server.dubbo;

import com.reajason.javaweb.asm.ClassInterfaceUtils;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import com.reajason.javaweb.utils.CommonUtil;
import com.reajason.javaweb.utils.StringUtils;

import com.reajason.javaweb.memshell.ShellType;

public class Dubbo extends AbstractServer {
    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(ShellType.APACHE_DUBBO_SERVICE, "com.reajason.javaweb.memshell.injector.dubbo.ApacheDubboServiceInjector")
                .addInjector(ShellType.ALIBABA_DUBBO_SERVICE, "com.reajason.javaweb.memshell.injector.dubbo.AlibabaDubboServiceInjector")
                .build();
    }

    /**
     * DubboService 马需要配套接口：生成接口 helper 类、给马字节码补上接口实现，
     * 且 urlPattern 默认取接口全限定名（Dubbo 服务按接口名注册）
     */
    @Override
    public byte[] postProcessShellBytes(byte[] shellBytes, ShellConfig shellConfig,
                                        ShellToolConfig shellToolConfig, InjectorConfig injectorConfig) {
        if (!shellConfig.getShellType().endsWith(ShellType.DUBBO_SERVICE)) {
            return shellBytes;
        }
        String packageName = CommonUtil.getPackageName(shellToolConfig.getShellClassName());
        String simpleName = CommonUtil.getSimpleName(shellToolConfig.getShellClassName());
        String interfaceName = packageName + ".I" + simpleName;
        injectorConfig.setInjectorHelperClassName(interfaceName);
        injectorConfig.setHelperClassBytes(DubboServiceInterfaceHelperGenerator.getBytes(interfaceName, shellConfig));
        shellBytes = ClassInterfaceUtils.addInterface(shellBytes, interfaceName);
        String urlPattern = injectorConfig.getUrlPattern();
        if (StringUtils.equalsAny(urlPattern, "/*", "/")
                || StringUtils.isBlank(urlPattern)) {
            injectorConfig.setUrlPattern(interfaceName);
        }
        return shellBytes;
    }
}
