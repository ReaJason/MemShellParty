package com.reajason.javaweb.integration;

import lombok.SneakyThrows;
import okhttp3.*;
import org.junit.jupiter.api.Assertions;

/**
 * @author ReaJason
 * @since 2024/11/30
 */
public class VulTool {

    @SneakyThrows
    public static void urlIsOk(String url) {
        Request request = new Request.Builder()
                .url(url).build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            Assertions.assertTrue(response.isSuccessful());
        }
    }


    @SneakyThrows
    public static void uploadJspFileToServer(String uploadUrl, String filename, String fileContent) {
        MediaType mediaType = MediaType.parse("text/plain");
        RequestBody fileRequestBody = RequestBody.create(fileContent, mediaType);
        MultipartBody requestBody = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("file", filename, fileRequestBody)
                .build();
        Request request = new Request.Builder()
                .url(uploadUrl).post(requestBody)
                .build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            Assertions.assertEquals(200, response.code());
        }
    }

    @SneakyThrows
    public static void postJS(String uploadUrl, String js) {
        RequestBody requestBody = new FormBody.Builder()
                .add("js", js)
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .url(uploadUrl).post(requestBody)
                .build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            Assertions.assertEquals(200, response.code());
        }
    }
}
