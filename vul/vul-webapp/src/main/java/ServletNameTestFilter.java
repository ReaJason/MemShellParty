import javax.servlet.*;
import java.io.IOException;

/**
 * @author ReaJason
 * @since 2026/1/11
 */
public class ServletNameTestFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {

    }
}
