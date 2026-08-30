import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.IOException;
import java.io.StringReader;

/**
 * @author ReaJason
 * @since 2026/8/30
 */
public class XSLTServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String data = req.getParameter("data");
        try {
            TransformerFactory factory = TransformerFactory.newInstance();
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(data)));
            transformer.transform(new StreamSource(new StringReader("<?xml version=\"1.0\" encoding=\"UTF-8\"?><root/>")),
                    new StreamResult(resp.getWriter()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
