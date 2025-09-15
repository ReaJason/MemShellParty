package com.reajason.javaweb.integration;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.junit.jupiter.api.Assertions;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
                .header("Referer", uploadUrl)
                .build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            System.out.println(response.body().string());
            assertEquals(200, response.code());
        }
    }

    @SneakyThrows
    public static void postIsOk(String uploadUrl, String data) {
        RequestBody requestBody = new FormBody.Builder()
                .add("data", data)
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Referer", uploadUrl)
                .url(uploadUrl).post(requestBody)
                .build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            System.out.println(response.body().string());
            Assertions.assertNotEquals(404, response.code());
        }
    }

    @SneakyThrows
    public static String post(String uploadUrl, String data) {
        RequestBody requestBody = new FormBody.Builder()
                .add("data", data)
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Referer", uploadUrl)
                .url(uploadUrl).post(requestBody)
                .build();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            return response.body().string();
        }
    }

    @SneakyThrows
    public static void xxlJobExecutor(String url, String data) {
        OkHttpClient client = new OkHttpClient();
        log.info(data);
        RequestBody body = RequestBody.create(data, MediaType.parse("application/json"));
        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .addHeader("Connection", "close")
                .addHeader("XXL-JOB-ACCESS-TOKEN", "default_token")
                .addHeader("Content-Type", "application/json")
                .build();
        try (Response response = client.newCall(request).execute()) {
            assertEquals(200, response.code());
            Thread.sleep(1000); // wait for job execute
            log.info(response.body().string());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
