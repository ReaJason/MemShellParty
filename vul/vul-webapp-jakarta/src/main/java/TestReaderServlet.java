import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2025/12/31
 */
public class TestReaderServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String one = req.getParameter("one");
        String body = null;
        BufferedReader reader = req.getReader();
        StringBuilder bodyBuilder = new StringBuilder();
        if (one != null) {
            int c;
            while ((c = reader.read()) != -1) {
                bodyBuilder.append((char) c);
            }
        } else {
            String line;
            while ((line = reader.readLine()) != null) {
                bodyBuilder.append(line);
            }
        }
        body = bodyBuilder.toString();
        resp.setContentType("text/html; charset=UTF-8");
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().println(body);
    }
}
