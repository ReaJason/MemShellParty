//package com.reajason.javaweb.integration.springcve;
//
//import okhttp3.HttpUrl;
//import okhttp3.OkHttpClient;
//import okhttp3.Request;
//import okhttp3.Response;
//import org.junit.jupiter.api.Test;
//import org.testcontainers.containers.DockerComposeContainer;
//import org.testcontainers.junit.jupiter.Container;
//import org.testcontainers.junit.jupiter.Testcontainers;
//
//import java.io.File;
//import java.util.Objects;
//
//import static org.junit.jupiter.api.Assertions.assertTrue;
//
///**
// * @author ReaJason
// * @since 2025/4/28
// */
//@Testcontainers
//public class CVE202222947 {
//    public static final String imageName = "spring-cve-2022-22947";
//
//    @Container
//    public static final DockerComposeContainer<?> compose =
//            new DockerComposeContainer<>(new File("docker-compose/spring/CVE-2022-22947.yaml"))
//                    .withExposedService("spring", 8080);
//
//    @Test
//    void test(){
//        compose.get
//        OkHttpClient okHttpClient = new OkHttpClient();
//        HttpUrl url = Objects.requireNonNull(HttpUrl.parse(entrypoint))
//                .newBuilder()
//                .addQueryParameter(shellConfig.getParamName(), payload)
//                .build();
//        Request request = new Request.Builder()
//                .url(url)
//                .get().build();
//
//        try (Response response = okHttpClient.newCall(request).execute()) {
//            String res = response.body().string();
//            System.out.println(res.trim());
//            assertTrue(res.contains("uid="));
//        }
//    }
//}
