import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2025/7/3
 */
@WebServlet("/xmlDecoder")
public class XmlDecoderServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String param = req.getParameter("data");
        ByteArrayInputStream inputStream = new ByteArrayInputStream(param.getBytes());
        XMLDecoder xmlDecoder = new XMLDecoder(inputStream);
        Object obj = xmlDecoder.readObject();
        resp.getWriter().println(obj);
        xmlDecoder.close();
    }
}
