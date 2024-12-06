package com.reajason.javaweb.integration;

import com.reajason.javaweb.config.CommandConfig;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/11/30
 */
@Slf4j
public class CommandShellTool {
    @SneakyThrows
    public static void testIsOk(String entrypoint, CommandConfig shellConfig) {
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
