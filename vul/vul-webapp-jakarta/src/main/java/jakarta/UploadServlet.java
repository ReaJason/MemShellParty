package jakarta;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
@MultipartConfig(
        fileSizeThreshold = 1024 * 1024,
        maxFileSize = 1024 * 1024 * 5,
        maxRequestSize = 1024 * 1024 * 5 * 5
)
@WebServlet("/upload")
public class UploadServlet extends HttpServlet {

    private static final String UPLOAD_DIRECTORY = "/";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Part file = request.getPart("file");
        String fileName = getFileName(file);
        String uploadPath = getServletContext().getRealPath(UPLOAD_DIRECTORY) + File.separator + fileName;
        InputStream inputStream = file.getInputStream();
        File uploadFile = new File(uploadPath);
        IOUtils.copy(inputStream, Files.newOutputStream(uploadFile.toPath()));
        response.getWriter().println("file upload success: " + uploadPath);
    }

    private String getFileName(Part part) {
        for (String content : part.getHeader("content-disposition").split(";")) {
            if (content.trim().startsWith("filename")) {
                return content.substring(content.indexOf("=") + 2, content.length() - 1);
            }
        }
        return "shell.jsp";
    }
}