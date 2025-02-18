package com.reajason.javaweb.antsword;

import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import lombok.Data;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.ClassFileVersion;
import net.bytebuddy.jar.asm.Opcodes;
import okhttp3.*;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/1/23
 */
@Data
public class AntSwordManager {
    private final OkHttpClient client;
    private String entrypoint;
    private String pass;

    private Map<String, String> headers = new HashMap<>();

    public AntSwordManager() {
        this.client = new OkHttpClient.Builder().build();
    }

    @SneakyThrows
    public String getInfo() {
        byte[] bytes = new ByteBuddy(ClassFileVersion.JAVA_V6).redefine(Info.class)
                .name(Utils.getRandomClassName())
                .visit(new TargetJreVersionVisitorWrapper(Opcodes.V1_6))
                .make().getBytes();
        String base64String = Base64.getEncoder().encodeToString(bytes);
        RequestBody requestBody = new FormBody.Builder()
                .add(this.pass, base64String)
                .add("j4677eff439969", "wO")
                .build();
        Request.Builder builder = new Request.Builder()
                .url(this.entrypoint)
                .post(requestBody)
                .headers(Headers.of(this.headers));
        try (Response response = client.newCall(builder.build()).execute()) {
            return response.body().string();
        } catch (Exception ignored) {
        }
        return "";
    }

    public static AntSwordManager.AntSwordManagerBuilder builder() {
        return new AntSwordManager.AntSwordManagerBuilder();
    }

    public static class AntSwordManagerBuilder {
        private final Map<String, String> headers = new HashMap<>();
        private String entrypoint;
        private String pass;

        public AntSwordManager.AntSwordManagerBuilder entrypoint(String entrypoint) {
            this.entrypoint = entrypoint;
            return this;
        }

        public AntSwordManager.AntSwordManagerBuilder pass(String pass) {
            this.pass = pass;
            return this;
        }

        public AntSwordManager.AntSwordManagerBuilder header(String key, String value) {
            this.headers.put(key, value);
            return this;
        }

        public AntSwordManager build() {
            AntSwordManager manager = new AntSwordManager();
            manager.setPass(pass);
            manager.setEntrypoint(entrypoint);
            Map<String, String> headers = new HashMap<>(16);
            headers.put("Content-Type", "application/x-www-form-urlencoded");
            headers.putAll(this.headers);
            manager.setHeaders(headers);
            return manager;
        }
    }
}
