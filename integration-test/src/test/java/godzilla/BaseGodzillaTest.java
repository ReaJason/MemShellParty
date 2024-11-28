package godzilla;

import com.reajason.javaweb.config.GodzillaShellConfig;
import com.reajason.javaweb.godzilla.GodzillaManager;
import lombok.SneakyThrows;
import okhttp3.*;
import org.junit.jupiter.api.Assertions;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/11/28
 */
public interface BaseGodzillaTest {

    OkHttpClient client = new OkHttpClient();

    @SneakyThrows
    default void verifyContainerResponse(String url) {
        Request request = new Request.Builder()
                .url(url).build();
        try (Response response = client.newCall(request).execute()) {
            Assertions.assertEquals(200, response.code());
        }
    }


    @SneakyThrows
    default void uploadJspFileToServer(String uploadUrl, String filename, String fileContent) {
        MediaType mediaType = MediaType.parse("text/plain");
        RequestBody fileRequestBody = RequestBody.create(fileContent, mediaType);
        MultipartBody requestBody = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("file", filename, fileRequestBody)
                .build();
        Request request = new Request.Builder()
                .url(uploadUrl).post(requestBody)
                .build();
        try (Response response = client.newCall(request).execute()) {
            Assertions.assertEquals(200, response.code());
        }
    }

    default void testGodzillaIsOk(String entrypoint, GodzillaShellConfig shellConfig) {
        try (GodzillaManager godzillaManager = GodzillaManager.builder()
                .entrypoint(entrypoint)
                .pass(shellConfig.getPass())
                .key(shellConfig.getKey())
                .header(shellConfig.getHeaderName(), shellConfig.getHeaderValue()).build()) {
            assertTrue(godzillaManager.start());
            assertTrue(godzillaManager.test());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
