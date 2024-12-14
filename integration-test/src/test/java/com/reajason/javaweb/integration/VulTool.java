package com.reajason.javaweb.integration;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.junit.jupiter.api.Assertions;

/**
 * @author ReaJason
 * @since 2024/11/30
 */
@Slf4j
public class VulTool {

    @SneakyThrows
    public static void urlIsOk(String url) {
        Request request = new Request.Builder()
                .url(url).build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            System.out.println(response.body().string());
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
            System.out.println(response.body().string());
            Assertions.assertEquals(200, response.code());
        }
    }

    @SneakyThrows
    public static void postData(String uploadUrl, String data) {
        RequestBody requestBody = new FormBody.Builder()
                .add("data", data)
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .url(uploadUrl).post(requestBody)
                .build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
//            log.info(response.body().string());
            Assertions.assertNotEquals(404, response.code());
        }
    }
}
