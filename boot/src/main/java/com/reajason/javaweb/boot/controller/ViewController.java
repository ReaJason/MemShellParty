package com.reajason.javaweb.boot.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * @author ReaJason
 * @since 2024/12/19
 */
@Controller
@Slf4j
public class ViewController {
    @GetMapping("/")
    public String index(){
        return "redirect:/ui";
    }

    @GetMapping({"/api/search", "/api/search.data"})
    @ResponseBody
    public String handleSearch(HttpServletRequest request, HttpServletResponse response) {
        String fullPath = request.getRequestURI();
        String relativePath = fullPath.substring(1);
        return renderFileData(relativePath, response);
    }

    @GetMapping({"/ui/docs/*.data", "/ui/*.data"})
    @ResponseBody
    public String handleDataFile(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fullPath = request.getRequestURI();
        String relativePath = fullPath.substring(4);
        return renderFileData(relativePath, response);
    }


    @GetMapping("/ui/**")
    public String handleHtmlView(HttpServletRequest request) {
        String fullPath = request.getRequestURI();
        if ("/ui".equals(fullPath) || "/ui/".equals(fullPath)) {
            return "index";
        }
        String viewPath = fullPath.substring(4);
        return viewPath + "/index";
    }

    private String renderFileData(String relativePath, HttpServletResponse response) {
        try {
            String templatePath = "templates/" + relativePath;
            ClassPathResource resource = new ClassPathResource(templatePath);
            if (!resource.exists()) {
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                return "File not found: " + relativePath;
            }
            response.setContentType(MediaType.TEXT_PLAIN_VALUE);
            response.setCharacterEncoding("UTF-8");
            InputStreamReader reader = new InputStreamReader(
                    resource.getInputStream(),
                    StandardCharsets.UTF_8
            );
            return FileCopyUtils.copyToString(reader);
        } catch (IOException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return "Error reading file: " + e.getMessage();
        }
    }
}
