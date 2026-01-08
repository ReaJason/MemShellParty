package jakarta;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * @author ReaJason
 * @since 2025/12/31
 */
public class TestInputStreamServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String one = req.getParameter("one");
        req.setCharacterEncoding("UTF-8");
        String body = null;
        InputStream inputStream = req.getInputStream();
        StringBuilder bodyBuilder = new StringBuilder();
        if (one != null) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            int b;
            while ((b = inputStream.read()) != -1) {
                outputStream.write(b);
            }
            bodyBuilder.append(outputStream.toString(StandardCharsets.UTF_8));
            outputStream.close();
        } else {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                bodyBuilder.append(new String(buffer, 0, bytesRead, StandardCharsets.UTF_8));
            }
        }
        body = bodyBuilder.toString();
        resp.setContentType("text/html; charset=UTF-8");
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().println(body);
    }
}
