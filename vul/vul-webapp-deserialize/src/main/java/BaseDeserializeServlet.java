import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Base64;
import java.util.List;

/**
 * @author ReaJason
 * @since 2025/2/19
 */
public abstract class BaseDeserializeServlet extends HttpServlet {

    abstract List<String> getDependentPaths();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
            String libPath = getServletContext().getRealPath("/WEB-INF/dep");
            URL[] urls = getDependentPaths().stream().map(path -> {
                try {
                    return new File(libPath + File.separator + path).toURI().toURL();
                } catch (MalformedURLException e) {
                    throw new RuntimeException(e);
                }
            }).toArray(URL[]::new);

            final URLClassLoader classLoader = new URLClassLoader(urls);

            String data = req.getParameter("data");
            ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(data));
            ObjectInputStream bis = new ObjectInputStream(inputStream) {
                @Override
                protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                    return Class.forName(desc.getName(), false, classLoader);
                }
            };
            bis.readObject();
            bis.close();
        } catch (Exception e) {
            if (e.getMessage().contains("InvocationTargetException")) {
                return;
            }
            throw new RuntimeException(e);
        }
    }
}
