package com.reajason.javaweb.boot.controller;

import com.reajason.javaweb.boot.entity.VersionInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.thymeleaf.util.StringUtils;

import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/2/2
 */
@RestController
@CrossOrigin("*")
@RequestMapping("/version")
public class VersionController {

    @Value("${spring.application.version}")
    private String version;

    private final RestTemplate restTemplate;

    public VersionController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping
    public VersionInfo version() {
        if ("dev".equals(version)) {
            return VersionInfo.builder()
                    .currentVersion(version)
                    .latestVersion(version).build();
        }
        String latestVersion = getLatestGithubRelease();
        return VersionInfo.builder()
                .currentVersion(version)
                .latestVersion(latestVersion)
                .hasUpdate(!StringUtils.equals(version, latestVersion))
                .build();
    }

    private String getLatestGithubRelease() {
        try {
            String latestVersion = tryFetchRelease("https://api.github.com");
            if (latestVersion != null) {
                return latestVersion;
            }
            latestVersion = tryFetchRelease("https://gh.llkk.cc/https://api.github.com");
            if (latestVersion != null) {
                return latestVersion;
            }
        } catch (Exception ignored) {
        }
        return version;
    }

    private String tryFetchRelease(String baseUrl) {
        String apiUrl = String.format("%s/repos/%s/%s/releases", baseUrl, "ReaJason", "MemShellParty");

        ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                apiUrl,
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<>() {
                }
        );
        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            List<Map<String, Object>> body = response.getBody();
            for (Map<String, Object> map : body) {
                String targetCommitish = (String) map.get("target_commitish");
                Boolean prerelease = (Boolean) map.get("prerelease");
                Boolean draft = (Boolean) map.get("draft");
                if ("master".equals(targetCommitish) && !prerelease && !draft) {
                    String tagName = (String) map.get("name");
                    return tagName.startsWith("v") ? tagName.substring(1) : tagName;
                }
            }
        }
        return null;
    }
}
