package litejavawebsite;

import java.io.*;
import java.util.*;
import java.util.function.Function;

public class NanoWebsite {
    private final HttpServer server;
    private String siteResourcePath;

    public NanoWebsite(int port, String siteResourcePath) {
        server = new HttpServer(port);
        this.siteResourcePath = siteResourcePath;
        server.setServeFunction(this::serve);
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop();
    }

    private NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
        String uri = new ExtractedUri(session).get();
        return NanoHTTPD.newChunkedResponse(NanoHTTPD.Response.Status.OK, new MimeType(uri).get(), new Resource(siteResourcePath + uri).get());
    }

    private final class ExtractedUri {
        private final litejavawebsite.NanoHTTPD.IHTTPSession session;

        public ExtractedUri(litejavawebsite.NanoHTTPD.IHTTPSession session) {
            this.session = session;
        }

        public String get() {
            String uri = session.getUri();
            if (uri.charAt(uri.length() - 1) == '/')
                return uri  + "Index.html";
            int extensionIndex = uri.lastIndexOf('.');
            if (extensionIndex == -1)
                return uri + ".html";
            return uri;
        }
    }

    private final class MimeType {
        public final Map<String, String> mimeTypes = new HashMap<String, String>() {{
            put("html", "text/html");
            put("js", "text/javascript");
            put("css", "text/css");
            put("ico", "image/x-icon");
        }};
        private final String name;

        public MimeType(String name) {
            this.name = name;
        }

        public String get() {

            return mimeTypes.get(new FileExtension(name).get());
        }
    }

    private final class FileExtension {
        private final String fileName;

        public FileExtension(String fileName) {
            this.fileName = fileName;
        }

        public String get() {
            int extensionIndex = fileName.lastIndexOf('.');
            return extensionIndex == 0 ? fileName : fileName.substring(extensionIndex + 1);
        }
    }

    private final class Resource {
        private final String name;

        public Resource(String name) {
            this.name = name;
        }

        public InputStream get() {
            return getClass().getResourceAsStream(name);
        }
    }

    private final class HttpServer extends litejavawebsite.NanoHTTPD {
        private Function<IHTTPSession, Response> _serveFunction;

        public HttpServer(final int port) {
            super(port);
        }

        public Response serve(IHTTPSession session) {
            if (_serveFunction != null)
                return _serveFunction.apply(session);
            return super.serve(session);
        }

        public void start() {
            try {
                start(SOCKET_READ_TIMEOUT, false);
            } catch (IOException e) {
                throw new RuntimeException("Unable to start Http server.", e);
            }
        }

        public void setServeFunction(final Function<IHTTPSession, Response> serveFunction) {
            _serveFunction = serveFunction;
        }
    }
}
