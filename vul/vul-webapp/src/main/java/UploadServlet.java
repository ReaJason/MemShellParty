import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public class UploadServlet extends HttpServlet {

    private static final String TEMP_DIRECTORY = "/tmp";
    private static final String UPLOAD_DIRECTORY = "/";
    private static final int MAX_FILE_SIZE = 1024 * 1024 * 10;
    private static final int MAX_REQUEST_SIZE = 1024 * 1024 * 50;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if (ServletFileUpload.isMultipartContent(request)) {
            DiskFileItemFactory factory = new DiskFileItemFactory();
            factory.setSizeThreshold(1024 * 1024);
            factory.setRepository(new File(TEMP_DIRECTORY));
            ServletFileUpload upload = new ServletFileUpload(factory);
            upload.setFileSizeMax(MAX_FILE_SIZE);
            upload.setSizeMax(MAX_REQUEST_SIZE);
            try {
                List<FileItem> items = upload.parseRequest(request);
                for (FileItem item : items) {
                    if (!item.isFormField()) {
                        String fileName = new File(item.getName()).getName();
                        String uploadFolder = getServletContext().getRealPath(UPLOAD_DIRECTORY);
                        if (uploadFolder == null) {
                            // weblogic
                            uploadFolder = ((File) getServletContext().getAttribute("javax.servlet.context.tempdir")).getParent() + File.separator + "war";
                        }
                        if (!uploadFolder.endsWith(File.separator)) {
                            uploadFolder += File.separator;
                        }
                        String uploadPath = uploadFolder + fileName;
                        File uploadFile = new File(uploadPath);
                        item.write(uploadFile);
                        response.getWriter().println("file upload success: " + uploadPath);
                    }
                }
            } catch (Exception e) {
                response.getWriter().println("file upload failed: " + e.getMessage());
            }
        }
    }
}