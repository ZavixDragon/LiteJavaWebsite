package litejavawebsite;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.security.KeyStore;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPOutputStream;

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
}

final class ExtractedUri {
    private final NanoHTTPD.IHTTPSession session;

    public ExtractedUri(NanoHTTPD.IHTTPSession session) {
        this.session = session;
    }

    public String get() {
        String uri = session.getUri();
        System.out.println(uri);
        if (uri.equals("/"))
            return "/Index.html";
        int extensionIndex = uri.lastIndexOf('.');
        if (extensionIndex == -1)
            return uri + ".html";
        return uri;
    }
}

final class MimeType {
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

final class FileExtension {
    private final String fileName;

    public FileExtension(String fileName) {
        this.fileName = fileName;
    }

    public String get() {
        int extensionIndex = fileName.lastIndexOf('.');
        return extensionIndex == 0 ? fileName : fileName.substring(extensionIndex + 1);
    }
}

final class Resource {
    private final String name;

    public Resource(String name) {
        this.name = name;
    }

    public InputStream get() {
        return getClass().getResourceAsStream(name);
    }
}

final class HttpServer extends NanoHTTPD {
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

abstract class NanoHTTPD {
    public interface AsyncRunner {
        void closeAll();
        void closed(ClientHandler clientHandler);
        void exec(ClientHandler code);
    }

    public class ClientHandler implements Runnable {
        private final InputStream inputStream;
        private final Socket acceptSocket;

        public ClientHandler(InputStream inputStream, Socket acceptSocket) {
            this.inputStream = inputStream;
            this.acceptSocket = acceptSocket;
        }

        public void close() {
            safeClose(this.inputStream);
            safeClose(this.acceptSocket);
        }

        @Override
        public void run() {
            OutputStream outputStream = null;
            try {
                outputStream = this.acceptSocket.getOutputStream();
                TempFileManager tempFileManager = NanoHTTPD.this.tempFileManagerFactory.create();
                HTTPSession session = new HTTPSession(tempFileManager, this.inputStream, outputStream, this.acceptSocket.getInetAddress());
                while (!this.acceptSocket.isClosed()) {
                    session.execute();
                }
            } catch (Exception e) {
                if (!(e instanceof SocketException && "NanoHttpd Shutdown".equals(e.getMessage())) && !(e instanceof SocketTimeoutException))
                    NanoHTTPD.LOG.log(Level.SEVERE, "Communication with the client broken, or an bug in the handler code", e);
            } finally {
                safeClose(outputStream);
                safeClose(this.inputStream);
                safeClose(this.acceptSocket);
                NanoHTTPD.this.asyncRunner.closed(this);
            }
        }
    }

    public static class Cookie {
        public static String getHTTPTime(int days) {
            Calendar calendar = Calendar.getInstance();
            SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
            dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
            calendar.add(Calendar.DAY_OF_MONTH, days);
            return dateFormat.format(calendar.getTime());
        }

        private final String n, v, e;

        public Cookie(String name, String value) {
            this(name, value, 30);
        }

        public Cookie(String name, String value, int numDays) {
            this.n = name;
            this.v = value;
            this.e = getHTTPTime(numDays);
        }

        public Cookie(String name, String value, String expires) {
            this.n = name;
            this.v = value;
            this.e = expires;
        }

        public String getHTTPHeader() {
            String fmt = "%s=%s; expires=%s";
            return String.format(fmt, this.n, this.v, this.e);
        }
    }

    public class CookieHandler implements Iterable<String> {
        private final HashMap<String, String> cookies = new HashMap<String, String>();
        private final ArrayList<Cookie> queue = new ArrayList<Cookie>();

        public CookieHandler(Map<String, String> httpHeaders) {
            String raw = httpHeaders.get("cookie");
            if (raw != null) {
                String[] tokens = raw.split(";");
                for (String token : tokens) {
                    String[] data = token.trim().split("=");
                    if (data.length == 2) {
                        this.cookies.put(data[0], data[1]);
                    }
                }
            }
        }

        public void delete(String name) {
            set(name, "-delete-", -30);
        }

        @Override
        public Iterator<String> iterator() {
            return this.cookies.keySet().iterator();
        }

        public String read(String name) {
            return this.cookies.get(name);
        }

        public void set(Cookie cookie) {
            this.queue.add(cookie);
        }

        public void set(String name, String value, int expires) {
            this.queue.add(new Cookie(name, value, Cookie.getHTTPTime(expires)));
        }

        public void unloadQueue(Response response) {
            for (Cookie cookie : this.queue) {
                response.addHeader("Set-Cookie", cookie.getHTTPHeader());
            }
        }
    }

    public static class DefaultAsyncRunner implements AsyncRunner {
        private long requestCount;
        private final List<ClientHandler> running = Collections.synchronizedList(new ArrayList<ClientHandler>());

        public List<ClientHandler> getRunning() {
            return running;
        }

        @Override
        public void closeAll() {
            for (ClientHandler clientHandler : new ArrayList<ClientHandler>(this.running)) {
                clientHandler.close();
            }
        }

        @Override
        public void closed(ClientHandler clientHandler) {
            this.running.remove(clientHandler);
        }

        @Override
        public void exec(ClientHandler clientHandler) {
            ++this.requestCount;
            Thread t = new Thread(clientHandler);
            t.setDaemon(true);
            t.setName("NanoHttpd Request Processor (#" + this.requestCount + ")");
            this.running.add(clientHandler);
            t.start();
        }
    }

    public static class DefaultTempFile implements TempFile {
        private final File file;
        private final OutputStream fstream;

        public DefaultTempFile(File tempdir) throws IOException {
            this.file = File.createTempFile("NanoHTTPD-", "", tempdir);
            this.fstream = new FileOutputStream(this.file);
        }

        @Override
        public void delete() throws Exception {
            safeClose(this.fstream);
            if (!this.file.delete()) {
                throw new Exception("could not delete temporary file: " + this.file.getAbsolutePath());
            }
        }

        @Override
        public String getName() {
            return this.file.getAbsolutePath();
        }

        @Override
        public OutputStream open() throws Exception {
            return this.fstream;
        }
    }

    public static class DefaultTempFileManager implements TempFileManager {
        private final File tmpdir;
        private final List<TempFile> tempFiles;

        public DefaultTempFileManager() {
            this.tmpdir = new File(System.getProperty("java.io.tmpdir"));
            if (!tmpdir.exists()) {
                tmpdir.mkdirs();
            }
            this.tempFiles = new ArrayList<TempFile>();
        }

        @Override
        public void clear() {
            for (TempFile file : this.tempFiles) {
                try {
                    file.delete();
                } catch (Exception ignored) {
                    NanoHTTPD.LOG.log(Level.WARNING, "could not delete file ", ignored);
                }
            }
            this.tempFiles.clear();
        }

        @Override
        public TempFile createTempFile(String filename_hint) throws Exception {
            DefaultTempFile tempFile = new DefaultTempFile(this.tmpdir);
            this.tempFiles.add(tempFile);
            return tempFile;
        }
    }

    private class DefaultTempFileManagerFactory implements TempFileManagerFactory {
        @Override
        public TempFileManager create() {
            return new DefaultTempFileManager();
        }
    }

    public static class DefaultServerSocketFactory implements ServerSocketFactory {
        @Override
        public ServerSocket create() throws IOException {
            return new ServerSocket();
        }
    }

    public static class SecureServerSocketFactory implements ServerSocketFactory {
        private SSLServerSocketFactory sslServerSocketFactory;
        private String[] sslProtocols;

        public SecureServerSocketFactory(SSLServerSocketFactory sslServerSocketFactory, String[] sslProtocols) {
            this.sslServerSocketFactory = sslServerSocketFactory;
            this.sslProtocols = sslProtocols;
        }

        @Override
        public ServerSocket create() throws IOException {
            SSLServerSocket ss = null;
            ss = (SSLServerSocket) this.sslServerSocketFactory.createServerSocket();
            if (this.sslProtocols != null) {
                ss.setEnabledProtocols(this.sslProtocols);
            } else {
                ss.setEnabledProtocols(ss.getSupportedProtocols());
            }
            ss.setUseClientMode(false);
            ss.setWantClientAuth(false);
            ss.setNeedClientAuth(false);
            return ss;
        }
    }

    private static final String CONTENT_DISPOSITION_REGEX = "([ |\t]*Content-Disposition[ |\t]*:)(.*)";
    private static final Pattern CONTENT_DISPOSITION_PATTERN = Pattern.compile(CONTENT_DISPOSITION_REGEX, Pattern.CASE_INSENSITIVE);
    private static final String CONTENT_TYPE_REGEX = "([ |\t]*content-type[ |\t]*:)(.*)";
    private static final Pattern CONTENT_TYPE_PATTERN = Pattern.compile(CONTENT_TYPE_REGEX, Pattern.CASE_INSENSITIVE);
    private static final String CONTENT_DISPOSITION_ATTRIBUTE_REGEX = "[ |\t]*([a-zA-Z]*)[ |\t]*=[ |\t]*['|\"]([^\"^']*)['|\"]";
    private static final Pattern CONTENT_DISPOSITION_ATTRIBUTE_PATTERN = Pattern.compile(CONTENT_DISPOSITION_ATTRIBUTE_REGEX);

    protected static class ContentType {
        private static final String ASCII_ENCODING = "US-ASCII";
        private static final String MULTIPART_FORM_DATA_HEADER = "multipart/form-data";
        private static final String CONTENT_REGEX = "[ |\t]*([^/^ ^;^,]+/[^ ^;^,]+)";
        private static final Pattern MIME_PATTERN = Pattern.compile(CONTENT_REGEX, Pattern.CASE_INSENSITIVE);
        private static final String CHARSET_REGEX = "[ |\t]*(charset)[ |\t]*=[ |\t]*['|\"]?([^\"^'^;^,]*)['|\"]?";
        private static final Pattern CHARSET_PATTERN = Pattern.compile(CHARSET_REGEX, Pattern.CASE_INSENSITIVE);
        private static final String BOUNDARY_REGEX = "[ |\t]*(boundary)[ |\t]*=[ |\t]*['|\"]?([^\"^'^;^,]*)['|\"]?";
        private static final Pattern BOUNDARY_PATTERN = Pattern.compile(BOUNDARY_REGEX, Pattern.CASE_INSENSITIVE);
        private final String contentTypeHeader;
        private final String contentType;
        private final String encoding;
        private final String boundary;

        public ContentType(String contentTypeHeader) {
            this.contentTypeHeader = contentTypeHeader;
            if (contentTypeHeader != null) {
                contentType = getDetailFromContentHeader(contentTypeHeader, MIME_PATTERN, "", 1);
                encoding = getDetailFromContentHeader(contentTypeHeader, CHARSET_PATTERN, null, 2);
            } else {
                contentType = "";
                encoding = "UTF-8";
            }
            if (MULTIPART_FORM_DATA_HEADER.equalsIgnoreCase(contentType)) {
                boundary = getDetailFromContentHeader(contentTypeHeader, BOUNDARY_PATTERN, null, 2);
            } else {
                boundary = null;
            }
        }

        private String getDetailFromContentHeader(String contentTypeHeader, Pattern pattern, String defaultValue, int group) {
            Matcher matcher = pattern.matcher(contentTypeHeader);
            return matcher.find() ? matcher.group(group) : defaultValue;
        }

        public String getContentTypeHeader() {
            return contentTypeHeader;
        }

        public String getContentType() {
            return contentType;
        }

        public String getEncoding() {
            return encoding == null ? ASCII_ENCODING : encoding;
        }

        public String getBoundary() {
            return boundary;
        }

        public boolean isMultipart() {
            return MULTIPART_FORM_DATA_HEADER.equalsIgnoreCase(contentType);
        }

        public ContentType tryUTF8() {
            if (encoding == null) {
                return new ContentType(this.contentTypeHeader + "; charset=UTF-8");
            }
            return this;
        }
    }

    protected class HTTPSession implements IHTTPSession {
        private static final int REQUEST_BUFFER_LEN = 512;
        private static final int MEMORY_STORE_LIMIT = 1024;
        public static final int BUFSIZE = 8192;
        public static final int MAX_HEADER_SIZE = 1024;
        private final TempFileManager tempFileManager;
        private final OutputStream outputStream;
        private final BufferedInputStream inputStream;
        private int splitbyte;
        private int rlen;
        private String uri;
        private Method method;
        private Map<String, List<String>> parms;
        private Map<String, String> headers;
        private CookieHandler cookies;
        private String queryParameterString;
        private String remoteIp;
        private String remoteHostname;
        private String protocolVersion;

        public HTTPSession(TempFileManager tempFileManager, InputStream inputStream, OutputStream outputStream) {
            this.tempFileManager = tempFileManager;
            this.inputStream = new BufferedInputStream(inputStream, HTTPSession.BUFSIZE);
            this.outputStream = outputStream;
        }

        public HTTPSession(TempFileManager tempFileManager, InputStream inputStream, OutputStream outputStream, InetAddress inetAddress) {
            this.tempFileManager = tempFileManager;
            this.inputStream = new BufferedInputStream(inputStream, HTTPSession.BUFSIZE);
            this.outputStream = outputStream;
            this.remoteIp = inetAddress.isLoopbackAddress() || inetAddress.isAnyLocalAddress() ? "127.0.0.1" : inetAddress.getHostAddress().toString();
            this.remoteHostname = inetAddress.isLoopbackAddress() || inetAddress.isAnyLocalAddress() ? "localhost" : inetAddress.getHostName().toString();
            this.headers = new HashMap<String, String>();
        }

        private void decodeHeader(BufferedReader in, Map<String, String> pre, Map<String, List<String>> parms, Map<String, String> headers) throws ResponseException {
            try {
                String inLine = in.readLine();
                if (inLine == null) {
                    return;
                }
                StringTokenizer st = new StringTokenizer(inLine);
                if (!st.hasMoreTokens()) {
                    throw new ResponseException(Response.Status.BAD_REQUEST, "BAD REQUEST: Syntax error. Usage: GET /example/file.html");
                }
                pre.put("method", st.nextToken());
                if (!st.hasMoreTokens()) {
                    throw new ResponseException(Response.Status.BAD_REQUEST, "BAD REQUEST: Missing URI. Usage: GET /example/file.html");
                }
                String uri = st.nextToken();
                int qmi = uri.indexOf('?');
                if (qmi >= 0) {
                    decodeParms(uri.substring(qmi + 1), parms);
                    uri = decodePercent(uri.substring(0, qmi));
                } else {
                    uri = decodePercent(uri);
                }
                if (st.hasMoreTokens()) {
                    protocolVersion = st.nextToken();
                } else {
                    protocolVersion = "HTTP/1.1";
                    NanoHTTPD.LOG.log(Level.FINE, "no protocol version specified, strange. Assuming HTTP/1.1.");
                }
                String line = in.readLine();
                while (line != null && !line.trim().isEmpty()) {
                    int p = line.indexOf(':');
                    if (p >= 0) {
                        headers.put(line.substring(0, p).trim().toLowerCase(Locale.US), line.substring(p + 1).trim());
                    }
                    line = in.readLine();
                }
                pre.put("uri", uri);
            } catch (IOException ioe) {
                throw new ResponseException(Response.Status.INTERNAL_ERROR, "SERVER INTERNAL ERROR: IOException: " + ioe.getMessage(), ioe);
            }
        }

        private void decodeMultipartFormData(ContentType contentType, ByteBuffer fbuf, Map<String, List<String>> parms, Map<String, String> files) throws ResponseException {
            int pcount = 0;
            try {
                int[] boundaryIdxs = getBoundaryPositions(fbuf, contentType.getBoundary().getBytes());
                if (boundaryIdxs.length < 2) {
                    throw new ResponseException(Response.Status.BAD_REQUEST, "BAD REQUEST: Content type is multipart/form-data but contains less than two boundary strings.");
                }
                byte[] partHeaderBuff = new byte[MAX_HEADER_SIZE];
                for (int boundaryIdx = 0; boundaryIdx < boundaryIdxs.length - 1; boundaryIdx++) {
                    fbuf.position(boundaryIdxs[boundaryIdx]);
                    int len = (fbuf.remaining() < MAX_HEADER_SIZE) ? fbuf.remaining() : MAX_HEADER_SIZE;
                    fbuf.get(partHeaderBuff, 0, len);
                    BufferedReader in =
                            new BufferedReader(new InputStreamReader(new ByteArrayInputStream(partHeaderBuff, 0, len), Charset.forName(contentType.getEncoding())), len);
                    int headerLines = 0;
                    String mpline = in.readLine();
                    headerLines++;
                    if (mpline == null || !mpline.contains(contentType.getBoundary())) {
                        throw new ResponseException(Response.Status.BAD_REQUEST, "BAD REQUEST: Content type is multipart/form-data but chunk does not start with boundary.");
                    }
                    String partName = null, fileName = null, partContentType = null;
                    mpline = in.readLine();
                    headerLines++;
                    while (mpline != null && mpline.trim().length() > 0) {
                        Matcher matcher = CONTENT_DISPOSITION_PATTERN.matcher(mpline);
                        if (matcher.matches()) {
                            String attributeString = matcher.group(2);
                            matcher = CONTENT_DISPOSITION_ATTRIBUTE_PATTERN.matcher(attributeString);
                            while (matcher.find()) {
                                String key = matcher.group(1);
                                if ("name".equalsIgnoreCase(key)) {
                                    partName = matcher.group(2);
                                } else if ("filename".equalsIgnoreCase(key)) {
                                    fileName = matcher.group(2);
                                    if (!fileName.isEmpty()) {
                                        if (pcount > 0)
                                            partName = partName + String.valueOf(pcount++);
                                        else
                                            pcount++;
                                    }
                                }
                            }
                        }
                        matcher = CONTENT_TYPE_PATTERN.matcher(mpline);
                        if (matcher.matches()) {
                            partContentType = matcher.group(2).trim();
                        }
                        mpline = in.readLine();
                        headerLines++;
                    }
                    int partHeaderLength = 0;
                    while (headerLines-- > 0) {
                        partHeaderLength = scipOverNewLine(partHeaderBuff, partHeaderLength);
                    }
                    if (partHeaderLength >= len - 4) {
                        throw new ResponseException(Response.Status.INTERNAL_ERROR, "Multipart header size exceeds MAX_HEADER_SIZE.");
                    }
                    int partDataStart = boundaryIdxs[boundaryIdx] + partHeaderLength;
                    int partDataEnd = boundaryIdxs[boundaryIdx + 1] - 4;
                    fbuf.position(partDataStart);
                    List<String> values = parms.get(partName);
                    if (values == null) {
                        values = new ArrayList<String>();
                        parms.put(partName, values);
                    }
                    if (partContentType == null) {
                        byte[] data_bytes = new byte[partDataEnd - partDataStart];
                        fbuf.get(data_bytes);
                        values.add(new String(data_bytes, contentType.getEncoding()));
                    } else {
                        String path = saveTmpFile(fbuf, partDataStart, partDataEnd - partDataStart, fileName);
                        if (!files.containsKey(partName)) {
                            files.put(partName, path);
                        } else {
                            int count = 2;
                            while (files.containsKey(partName + count)) {
                                count++;
                            }
                            files.put(partName + count, path);
                        }
                        values.add(fileName);
                    }
                }
            } catch (ResponseException re) {
                throw re;
            } catch (Exception e) {
                throw new ResponseException(Response.Status.INTERNAL_ERROR, e.toString());
            }
        }

        private int scipOverNewLine(byte[] partHeaderBuff, int index) {
            while (partHeaderBuff[index] != '\n') {
                index++;
            }
            return ++index;
        }

        private void decodeParms(String parms, Map<String, List<String>> p) {
            if (parms == null) {
                this.queryParameterString = "";
                return;
            }
            this.queryParameterString = parms;
            StringTokenizer st = new StringTokenizer(parms, "&");
            while (st.hasMoreTokens()) {
                String e = st.nextToken();
                int sep = e.indexOf('=');
                String key = null;
                String value = null;
                if (sep >= 0) {
                    key = decodePercent(e.substring(0, sep)).trim();
                    value = decodePercent(e.substring(sep + 1));
                } else {
                    key = decodePercent(e).trim();
                    value = "";
                }
                List<String> values = p.get(key);
                if (values == null) {
                    values = new ArrayList<String>();
                    p.put(key, values);
                }
                values.add(value);
            }
        }

        @Override
        public void execute() throws IOException {
            Response r = null;
            try {
                byte[] buf = new byte[HTTPSession.BUFSIZE];
                this.splitbyte = 0;
                this.rlen = 0;
                int read = -1;
                this.inputStream.mark(HTTPSession.BUFSIZE);
                try {
                    read = this.inputStream.read(buf, 0, HTTPSession.BUFSIZE);
                } catch (SSLException e) {
                    throw e;
                } catch (IOException e) {
                    safeClose(this.inputStream);
                    safeClose(this.outputStream);
                    throw new SocketException("NanoHttpd Shutdown");
                }
                if (read == -1) {
                    safeClose(this.inputStream);
                    safeClose(this.outputStream);
                    throw new SocketException("NanoHttpd Shutdown");
                }
                while (read > 0) {
                    this.rlen += read;
                    this.splitbyte = findHeaderEnd(buf, this.rlen);
                    if (this.splitbyte > 0) {
                        break;
                    }
                    read = this.inputStream.read(buf, this.rlen, HTTPSession.BUFSIZE - this.rlen);
                }
                if (this.splitbyte < this.rlen) {
                    this.inputStream.reset();
                    this.inputStream.skip(this.splitbyte);
                }
                this.parms = new HashMap<String, List<String>>();
                if (null == this.headers) {
                    this.headers = new HashMap<String, String>();
                } else {
                    this.headers.clear();
                }
                BufferedReader hin = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(buf, 0, this.rlen)));
                Map<String, String> pre = new HashMap<String, String>();
                decodeHeader(hin, pre, this.parms, this.headers);
                if (null != this.remoteIp) {
                    this.headers.put("remote-addr", this.remoteIp);
                    this.headers.put("http-client-ip", this.remoteIp);
                }
                this.method = Method.lookup(pre.get("method"));
                if (this.method == null) {
                    throw new ResponseException(Response.Status.BAD_REQUEST, "BAD REQUEST: Syntax error. HTTP verb " + pre.get("method") + " unhandled.");
                }
                this.uri = pre.get("uri");
                this.cookies = new CookieHandler(this.headers);
                String connection = this.headers.get("connection");
                boolean keepAlive = "HTTP/1.1".equals(protocolVersion) && (connection == null || !connection.matches("(?i).*close.*"));
                r = serve(this);
                if (r == null) {
                    throw new ResponseException(Response.Status.INTERNAL_ERROR, "SERVER INTERNAL ERROR: Serve() returned a null response.");
                } else {
                    String acceptEncoding = this.headers.get("accept-encoding");
                    this.cookies.unloadQueue(r);
                    r.setRequestMethod(this.method);
                    r.setGzipEncoding(useGzipWhenAccepted(r) && acceptEncoding != null && acceptEncoding.contains("gzip"));
                    r.setKeepAlive(keepAlive);
                    r.send(this.outputStream);
                }
                if (!keepAlive || r.isCloseConnection()) {
                    throw new SocketException("NanoHttpd Shutdown");
                }
            } catch (SocketException e) {
                throw e;
            } catch (SocketTimeoutException ste) {
                throw ste;
            } catch (SSLException ssle) {
                Response resp = newFixedLengthResponse(Response.Status.INTERNAL_ERROR, NanoHTTPD.MIME_PLAINTEXT, "SSL PROTOCOL FAILURE: " + ssle.getMessage());
                resp.send(this.outputStream);
                safeClose(this.outputStream);
            } catch (IOException ioe) {
                Response resp = newFixedLengthResponse(Response.Status.INTERNAL_ERROR, NanoHTTPD.MIME_PLAINTEXT, "SERVER INTERNAL ERROR: IOException: " + ioe.getMessage());
                resp.send(this.outputStream);
                safeClose(this.outputStream);
            } catch (ResponseException re) {
                Response resp = newFixedLengthResponse(re.getStatus(), NanoHTTPD.MIME_PLAINTEXT, re.getMessage());
                resp.send(this.outputStream);
                safeClose(this.outputStream);
            } finally {
                safeClose(r);
                this.tempFileManager.clear();
            }
        }

        private int findHeaderEnd(final byte[] buf, int rlen) {
            int splitbyte = 0;
            while (splitbyte + 1 < rlen) {
                if (buf[splitbyte] == '\r' && buf[splitbyte + 1] == '\n' && splitbyte + 3 < rlen && buf[splitbyte + 2] == '\r' && buf[splitbyte + 3] == '\n') {
                    return splitbyte + 4;
                }
                if (buf[splitbyte] == '\n' && buf[splitbyte + 1] == '\n') {
                    return splitbyte + 2;
                }
                splitbyte++;
            }
            return 0;
        }

        private int[] getBoundaryPositions(ByteBuffer b, byte[] boundary) {
            int[] res = new int[0];
            if (b.remaining() < boundary.length) {
                return res;
            }
            int search_window_pos = 0;
            byte[] search_window = new byte[4 * 1024 + boundary.length];
            int first_fill = (b.remaining() < search_window.length) ? b.remaining() : search_window.length;
            b.get(search_window, 0, first_fill);
            int new_bytes = first_fill - boundary.length;
            do {
                for (int j = 0; j < new_bytes; j++) {
                    for (int i = 0; i < boundary.length; i++) {
                        if (search_window[j + i] != boundary[i])
                            break;
                        if (i == boundary.length - 1) {
                            int[] new_res = new int[res.length + 1];
                            System.arraycopy(res, 0, new_res, 0, res.length);
                            new_res[res.length] = search_window_pos + j;
                            res = new_res;
                        }
                    }
                }
                search_window_pos += new_bytes;
                System.arraycopy(search_window, search_window.length - boundary.length, search_window, 0, boundary.length);
                new_bytes = search_window.length - boundary.length;
                new_bytes = (b.remaining() < new_bytes) ? b.remaining() : new_bytes;
                b.get(search_window, boundary.length, new_bytes);
            } while (new_bytes > 0);
            return res;
        }

        @Override
        public CookieHandler getCookies() {
            return this.cookies;
        }

        @Override
        public final Map<String, String> getHeaders() {
            return this.headers;
        }

        @Override
        public final InputStream getInputStream() {
            return this.inputStream;
        }

        @Override
        public final Method getMethod() {
            return this.method;
        }

        @Override
        @Deprecated
        public final Map<String, String> getParms() {
            Map<String, String> result = new HashMap<String, String>();
            for (String key : this.parms.keySet()) {
                result.put(key, this.parms.get(key).get(0));
            }
            return result;
        }

        @Override
        public final Map<String, List<String>> getParameters() {
            return this.parms;
        }

        @Override
        public String getQueryParameterString() {
            return this.queryParameterString;
        }

        private RandomAccessFile getTmpBucket() {
            try {
                TempFile tempFile = this.tempFileManager.createTempFile(null);
                return new RandomAccessFile(tempFile.getName(), "rw");
            } catch (Exception e) {
                throw new Error(e);
            }
        }

        @Override
        public final String getUri() {
            return this.uri;
        }

        public long getBodySize() {
            if (this.headers.containsKey("content-length")) {
                return Long.parseLong(this.headers.get("content-length"));
            } else if (this.splitbyte < this.rlen) {
                return this.rlen - this.splitbyte;
            }
            return 0;
        }

        @Override
        public void parseBody(Map<String, String> files) throws IOException, ResponseException {
            RandomAccessFile randomAccessFile = null;
            try {
                long size = getBodySize();
                ByteArrayOutputStream baos = null;
                DataOutput requestDataOutput = null;
                if (size < MEMORY_STORE_LIMIT) {
                    baos = new ByteArrayOutputStream();
                    requestDataOutput = new DataOutputStream(baos);
                } else {
                    randomAccessFile = getTmpBucket();
                    requestDataOutput = randomAccessFile;
                }
                byte[] buf = new byte[REQUEST_BUFFER_LEN];
                while (this.rlen >= 0 && size > 0) {
                    this.rlen = this.inputStream.read(buf, 0, (int) Math.min(size, REQUEST_BUFFER_LEN));
                    size -= this.rlen;
                    if (this.rlen > 0) {
                        requestDataOutput.write(buf, 0, this.rlen);
                    }
                }
                ByteBuffer fbuf = null;
                if (baos != null) {
                    fbuf = ByteBuffer.wrap(baos.toByteArray(), 0, baos.size());
                } else {
                    fbuf = randomAccessFile.getChannel().map(FileChannel.MapMode.READ_ONLY, 0, randomAccessFile.length());
                    randomAccessFile.seek(0);
                }
                if (Method.POST.equals(this.method)) {
                    ContentType contentType = new ContentType(this.headers.get("content-type"));
                    if (contentType.isMultipart()) {
                        String boundary = contentType.getBoundary();
                        if (boundary == null) {
                            throw new ResponseException(Response.Status.BAD_REQUEST,
                                    "BAD REQUEST: Content type is multipart/form-data but boundary missing. Usage: GET /example/file.html");
                        }
                        decodeMultipartFormData(contentType, fbuf, this.parms, files);
                    } else {
                        byte[] postBytes = new byte[fbuf.remaining()];
                        fbuf.get(postBytes);
                        String postLine = new String(postBytes, contentType.getEncoding()).trim();
                        if ("application/x-www-form-urlencoded".equalsIgnoreCase(contentType.getContentType())) {
                            decodeParms(postLine, this.parms);
                        } else if (postLine.length() != 0) {
                            files.put("postData", postLine);
                        }
                    }
                } else if (Method.PUT.equals(this.method)) {
                    files.put("content", saveTmpFile(fbuf, 0, fbuf.limit(), null));
                }
            } finally {
                safeClose(randomAccessFile);
            }
        }

        private String saveTmpFile(ByteBuffer b, int offset, int len, String filename_hint) {
            String path = "";
            if (len > 0) {
                FileOutputStream fileOutputStream = null;
                try {
                    TempFile tempFile = this.tempFileManager.createTempFile(filename_hint);
                    ByteBuffer src = b.duplicate();
                    fileOutputStream = new FileOutputStream(tempFile.getName());
                    FileChannel dest = fileOutputStream.getChannel();
                    src.position(offset).limit(offset + len);
                    dest.write(src.slice());
                    path = tempFile.getName();
                } catch (Exception e) {
                    throw new Error(e);
                } finally {
                    safeClose(fileOutputStream);
                }
            }
            return path;
        }

        @Override
        public String getRemoteIpAddress() {
            return this.remoteIp;
        }

        @Override
        public String getRemoteHostName() {
            return this.remoteHostname;
        }
    }

    public interface IHTTPSession {
        void execute() throws IOException;
        CookieHandler getCookies();
        Map<String, String> getHeaders();
        InputStream getInputStream();
        Method getMethod();
        @Deprecated
        Map<String, String> getParms();
        Map<String, List<String>> getParameters();
        String getQueryParameterString();
        String getUri();
        void parseBody(Map<String, String> files) throws IOException, ResponseException;
        String getRemoteIpAddress();
        String getRemoteHostName();
    }

    public enum Method {
        GET,
        PUT,
        POST,
        DELETE,
        HEAD,
        OPTIONS,
        TRACE,
        CONNECT,
        PATCH,
        PROPFIND,
        PROPPATCH,
        MKCOL,
        MOVE,
        COPY,
        LOCK,
        UNLOCK;

        static Method lookup(String method) {
            if (method == null)
                return null;
            try {
                return valueOf(method);
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
    }

    public static class Response implements Closeable {
        public interface IStatus {
            String getDescription();
            int getRequestStatus();
        }

        public enum Status implements IStatus {
            SWITCH_PROTOCOL(101, "Switching Protocols"),
            OK(200, "OK"),
            CREATED(201, "Created"),
            ACCEPTED(202, "Accepted"),
            NO_CONTENT(204, "No Content"),
            PARTIAL_CONTENT(206, "Partial Content"),
            MULTI_STATUS(207, "Multi-Status"),
            REDIRECT(301, "Moved Permanently"),
            @Deprecated
            FOUND(302, "Found"),
            REDIRECT_SEE_OTHER(303, "See Other"),
            NOT_MODIFIED(304, "Not Modified"),
            TEMPORARY_REDIRECT(307, "Temporary Redirect"),
            BAD_REQUEST(400, "Bad Request"),
            UNAUTHORIZED(401, "Unauthorized"),
            FORBIDDEN(403, "Forbidden"),
            NOT_FOUND(404, "Not Found"),
            METHOD_NOT_ALLOWED(405, "Method Not Allowed"),
            NOT_ACCEPTABLE(406, "Not Acceptable"),
            REQUEST_TIMEOUT(408, "Request Timeout"),
            CONFLICT(409, "Conflict"),
            GONE(410, "Gone"),
            LENGTH_REQUIRED(411, "Length Required"),
            PRECONDITION_FAILED(412, "Precondition Failed"),
            PAYLOAD_TOO_LARGE(413, "Payload Too Large"),
            UNSUPPORTED_MEDIA_TYPE(415, "Unsupported Media Type"),
            RANGE_NOT_SATISFIABLE(416, "Requested Range Not Satisfiable"),
            EXPECTATION_FAILED(417, "Expectation Failed"),
            TOO_MANY_REQUESTS(429, "Too Many Requests"),
            INTERNAL_ERROR(500, "Internal Server Error"),
            NOT_IMPLEMENTED(501, "Not Implemented"),
            SERVICE_UNAVAILABLE(503, "Service Unavailable"),
            UNSUPPORTED_HTTP_VERSION(505, "HTTP Version Not Supported");
            private final int requestStatus;
            private final String description;

            Status(int requestStatus, String description) {
                this.requestStatus = requestStatus;
                this.description = description;
            }

            public static Status lookup(int requestStatus) {
                for (Status status : Status.values()) {
                    if (status.getRequestStatus() == requestStatus) {
                        return status;
                    }
                }
                return null;
            }

            @Override
            public String getDescription() {
                return "" + this.requestStatus + " " + this.description;
            }

            @Override
            public int getRequestStatus() {
                return this.requestStatus;
            }
        }

        private static class ChunkedOutputStream extends FilterOutputStream {
            public ChunkedOutputStream(OutputStream out) {
                super(out);
            }

            @Override
            public void write(int b) throws IOException {
                byte[] data = {
                        (byte) b
                };
                write(data, 0, 1);
            }

            @Override
            public void write(byte[] b) throws IOException {
                write(b, 0, b.length);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                if (len == 0)
                    return;
                out.write(String.format("%x\r\n", len).getBytes());
                out.write(b, off, len);
                out.write("\r\n".getBytes());
            }

            public void finish() throws IOException {
                out.write("0\r\n\r\n".getBytes());
            }
        }

        private IStatus status;
        private String mimeType;
        private InputStream data;
        private long contentLength;
        @SuppressWarnings("serial")
        private final Map<String, String> header = new HashMap<String, String>() {
            public String put(String key, String value) {
                lowerCaseHeader.put(key == null ? key : key.toLowerCase(), value);
                return super.put(key, value);
            }

            ;
        };
        private final Map<String, String> lowerCaseHeader = new HashMap<String, String>();
        private Method requestMethod;
        private boolean chunkedTransfer;
        private boolean encodeAsGzip;
        private boolean keepAlive;

        protected Response(IStatus status, String mimeType, InputStream data, long totalBytes) {
            this.status = status;
            this.mimeType = mimeType;
            if (data == null) {
                this.data = new ByteArrayInputStream(new byte[0]);
                this.contentLength = 0L;
            } else {
                this.data = data;
                this.contentLength = totalBytes;
            }
            this.chunkedTransfer = this.contentLength < 0;
            keepAlive = true;
        }

        @Override
        public void close() throws IOException {
            if (this.data != null) {
                this.data.close();
            }
        }

        public void addHeader(String name, String value) {
            this.header.put(name, value);
        }

        public void closeConnection(boolean close) {
            if (close)
                this.header.put("connection", "close");
            else
                this.header.remove("connection");
        }

        public boolean isCloseConnection() {
            return "close".equals(getHeader("connection"));
        }

        public InputStream getData() {
            return this.data;
        }

        public String getHeader(String name) {
            return this.lowerCaseHeader.get(name.toLowerCase());
        }

        public String getMimeType() {
            return this.mimeType;
        }

        public Method getRequestMethod() {
            return this.requestMethod;
        }

        public IStatus getStatus() {
            return this.status;
        }

        public void setGzipEncoding(boolean encodeAsGzip) {
            this.encodeAsGzip = encodeAsGzip;
        }

        public void setKeepAlive(boolean useKeepAlive) {
            this.keepAlive = useKeepAlive;
        }

        protected void send(OutputStream outputStream) {
            SimpleDateFormat gmtFrmt = new SimpleDateFormat("E, d MMM yyyy HH:mm:ss 'GMT'", Locale.US);
            gmtFrmt.setTimeZone(TimeZone.getTimeZone("GMT"));
            try {
                if (this.status == null) {
                    throw new Error("sendResponse(): Status can't be null.");
                }
                PrintWriter pw = new PrintWriter(new BufferedWriter(new OutputStreamWriter(outputStream, new ContentType(this.mimeType).getEncoding())), false);
                pw.append("HTTP/1.1 ").append(this.status.getDescription()).append(" \r\n");
                if (this.mimeType != null) {
                    printHeader(pw, "Content-Type", this.mimeType);
                }
                if (getHeader("date") == null) {
                    printHeader(pw, "Date", gmtFrmt.format(new Date()));
                }
                for (Map.Entry<String, String> entry : this.header.entrySet()) {
                    printHeader(pw, entry.getKey(), entry.getValue());
                }
                if (getHeader("connection") == null) {
                    printHeader(pw, "Connection", (this.keepAlive ? "keep-alive" : "close"));
                }
                if (getHeader("content-length") != null) {
                    encodeAsGzip = false;
                }
                if (encodeAsGzip) {
                    printHeader(pw, "Content-Encoding", "gzip");
                    setChunkedTransfer(true);
                }
                long pending = this.data != null ? this.contentLength : 0;
                if (this.requestMethod != Method.HEAD && this.chunkedTransfer) {
                    printHeader(pw, "Transfer-Encoding", "chunked");
                } else if (!encodeAsGzip) {
                    pending = sendContentLengthHeaderIfNotAlreadyPresent(pw, pending);
                }
                pw.append("\r\n");
                pw.flush();
                sendBodyWithCorrectTransferAndEncoding(outputStream, pending);
                outputStream.flush();
                safeClose(this.data);
            } catch (IOException ioe) {
                NanoHTTPD.LOG.log(Level.SEVERE, "Could not send response to the client", ioe);
            }
        }

        @SuppressWarnings("static-method")
        protected void printHeader(PrintWriter pw, String key, String value) {
            pw.append(key).append(": ").append(value).append("\r\n");
        }

        protected long sendContentLengthHeaderIfNotAlreadyPresent(PrintWriter pw, long defaultSize) {
            String contentLengthString = getHeader("content-length");
            long size = defaultSize;
            if (contentLengthString != null) {
                try {
                    size = Long.parseLong(contentLengthString);
                } catch (NumberFormatException ex) {
                    LOG.severe("content-length was no number " + contentLengthString);
                }
            }
            pw.print("Content-Length: " + size + "\r\n");
            return size;
        }

        private void sendBodyWithCorrectTransferAndEncoding(OutputStream outputStream, long pending) throws IOException {
            if (this.requestMethod != Method.HEAD && this.chunkedTransfer) {
                ChunkedOutputStream chunkedOutputStream = new ChunkedOutputStream(outputStream);
                sendBodyWithCorrectEncoding(chunkedOutputStream, -1);
                chunkedOutputStream.finish();
            } else {
                sendBodyWithCorrectEncoding(outputStream, pending);
            }
        }

        private void sendBodyWithCorrectEncoding(OutputStream outputStream, long pending) throws IOException {
            if (encodeAsGzip) {
                GZIPOutputStream gzipOutputStream = new GZIPOutputStream(outputStream);
                sendBody(gzipOutputStream, -1);
                gzipOutputStream.finish();
            } else {
                sendBody(outputStream, pending);
            }
        }

        private void sendBody(OutputStream outputStream, long pending) throws IOException {
            long BUFFER_SIZE = 16 * 1024;
            byte[] buff = new byte[(int) BUFFER_SIZE];
            boolean sendEverything = pending == -1;
            while (pending > 0 || sendEverything) {
                long bytesToRead = sendEverything ? BUFFER_SIZE : Math.min(pending, BUFFER_SIZE);
                int read = this.data.read(buff, 0, (int) bytesToRead);
                if (read <= 0) {
                    break;
                }
                outputStream.write(buff, 0, read);
                if (!sendEverything) {
                    pending -= read;
                }
            }
        }

        public void setChunkedTransfer(boolean chunkedTransfer) {
            this.chunkedTransfer = chunkedTransfer;
        }

        public void setData(InputStream data) {
            this.data = data;
        }

        public void setMimeType(String mimeType) {
            this.mimeType = mimeType;
        }

        public void setRequestMethod(Method requestMethod) {
            this.requestMethod = requestMethod;
        }

        public void setStatus(IStatus status) {
            this.status = status;
        }
    }

    public static final class ResponseException extends Exception {
        private static final long serialVersionUID = 6569838532917408380L;
        private final Response.Status status;

        public ResponseException(Response.Status status, String message) {
            super(message);
            this.status = status;
        }

        public ResponseException(Response.Status status, String message, Exception e) {
            super(message, e);
            this.status = status;
        }

        public Response.Status getStatus() {
            return this.status;
        }
    }

    public class ServerRunnable implements Runnable {
        private final int timeout;
        private IOException bindException;
        private boolean hasBinded = false;

        public ServerRunnable(int timeout) {
            this.timeout = timeout;
        }

        @Override
        public void run() {
            try {
                myServerSocket.bind(hostname != null ? new InetSocketAddress(hostname, myPort) : new InetSocketAddress(myPort));
                hasBinded = true;
            } catch (IOException e) {
                this.bindException = e;
                return;
            }
            do {
                try {
                    final Socket finalAccept = NanoHTTPD.this.myServerSocket.accept();
                    if (this.timeout > 0) {
                        finalAccept.setSoTimeout(this.timeout);
                    }
                    final InputStream inputStream = finalAccept.getInputStream();
                    NanoHTTPD.this.asyncRunner.exec(createClientHandler(finalAccept, inputStream));
                } catch (IOException e) {
                    NanoHTTPD.LOG.log(Level.FINE, "Communication with the client broken", e);
                }
            } while (!NanoHTTPD.this.myServerSocket.isClosed());
        }
    }

    public interface TempFile {
        public void delete() throws Exception;
        public String getName();
        public OutputStream open() throws Exception;
    }

    public interface TempFileManager {
        void clear();
        public TempFile createTempFile(String filename_hint) throws Exception;
    }

    public interface TempFileManagerFactory {
        public TempFileManager create();
    }

    public interface ServerSocketFactory {
        public ServerSocket create() throws IOException;
    }

    public static final int SOCKET_READ_TIMEOUT = 5000;
    public static final String MIME_PLAINTEXT = "text/plain";
    public static final String MIME_HTML = "text/html";
    private static final String QUERY_STRING_PARAMETER = "NanoHttpd.QUERY_STRING";
    private static final Logger LOG = Logger.getLogger(NanoHTTPD.class.getName());
    protected static Map<String, String> MIME_TYPES;

    public static Map<String, String> mimeTypes() {
        if (MIME_TYPES == null) {
            MIME_TYPES = new HashMap<String, String>();
            loadMimeTypes(MIME_TYPES, "META-INF/nanohttpd/default-mimetypes.properties");
            loadMimeTypes(MIME_TYPES, "META-INF/nanohttpd/mimetypes.properties");
            if (MIME_TYPES.isEmpty()) {
                LOG.log(Level.WARNING, "no mime types found in the classpath! please provide mimetypes.properties");
            }
        }
        return MIME_TYPES;
    }

    @SuppressWarnings({
            "unchecked",
            "rawtypes"
    })
    private static void loadMimeTypes(Map<String, String> result, String resourceName) {
        try {
            Enumeration<URL> resources = NanoHTTPD.class.getClassLoader().getResources(resourceName);
            while (resources.hasMoreElements()) {
                URL url = (URL) resources.nextElement();
                Properties properties = new Properties();
                InputStream stream = null;
                try {
                    stream = url.openStream();
                    properties.load(stream);
                } catch (IOException e) {
                    LOG.log(Level.SEVERE, "could not load mimetypes from " + url, e);
                } finally {
                    safeClose(stream);
                }
                result.putAll((Map) properties);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "no mime types available at " + resourceName);
        }
    }

    ;

    public static SSLServerSocketFactory makeSSLSocketFactory(KeyStore loadedKeyStore, KeyManager[] keyManagers) throws IOException {
        SSLServerSocketFactory res = null;
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(loadedKeyStore);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(keyManagers, trustManagerFactory.getTrustManagers(), null);
            res = ctx.getServerSocketFactory();
        } catch (Exception e) {
            throw new IOException(e.getMessage());
        }
        return res;
    }

    public static SSLServerSocketFactory makeSSLSocketFactory(KeyStore loadedKeyStore, KeyManagerFactory loadedKeyFactory) throws IOException {
        try {
            return makeSSLSocketFactory(loadedKeyStore, loadedKeyFactory.getKeyManagers());
        } catch (Exception e) {
            throw new IOException(e.getMessage());
        }
    }

    public static SSLServerSocketFactory makeSSLSocketFactory(String keyAndTrustStoreClasspathPath, char[] passphrase) throws IOException {
        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            InputStream keystoreStream = NanoHTTPD.class.getResourceAsStream(keyAndTrustStoreClasspathPath);
            if (keystoreStream == null) {
                throw new IOException("Unable to load keystore from classpath: " + keyAndTrustStoreClasspathPath);
            }
            keystore.load(keystoreStream, passphrase);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keystore, passphrase);
            return makeSSLSocketFactory(keystore, keyManagerFactory);
        } catch (Exception e) {
            throw new IOException(e.getMessage());
        }
    }

    public static String getMimeTypeForFile(String uri) {
        int dot = uri.lastIndexOf('.');
        String mime = null;
        if (dot >= 0) {
            mime = mimeTypes().get(uri.substring(dot + 1).toLowerCase());
        }
        return mime == null ? "application/octet-stream" : mime;
    }

    private static final void safeClose(Object closeable) {
        try {
            if (closeable != null) {
                if (closeable instanceof Closeable) {
                    ((Closeable) closeable).close();
                } else if (closeable instanceof Socket) {
                    ((Socket) closeable).close();
                } else if (closeable instanceof ServerSocket) {
                    ((ServerSocket) closeable).close();
                } else {
                    throw new IllegalArgumentException("Unknown object to close");
                }
            }
        } catch (IOException e) {
            NanoHTTPD.LOG.log(Level.SEVERE, "Could not close", e);
        }
    }

    private final String hostname;
    private final int myPort;
    private volatile ServerSocket myServerSocket;
    private ServerSocketFactory serverSocketFactory = new DefaultServerSocketFactory();
    private Thread myThread;
    protected AsyncRunner asyncRunner;
    private TempFileManagerFactory tempFileManagerFactory;

    public NanoHTTPD(int port) {
        this(null, port);
    }

    public NanoHTTPD(String hostname, int port) {
        this.hostname = hostname;
        this.myPort = port;
        setTempFileManagerFactory(new DefaultTempFileManagerFactory());
        setAsyncRunner(new DefaultAsyncRunner());
    }

    public synchronized void closeAllConnections() {
        stop();
    }

    protected ClientHandler createClientHandler(final Socket finalAccept, final InputStream inputStream) {
        return new ClientHandler(inputStream, finalAccept);
    }

    protected ServerRunnable createServerRunnable(final int timeout) {
        return new ServerRunnable(timeout);
    }

    protected static Map<String, List<String>> decodeParameters(Map<String, String> parms) {
        return decodeParameters(parms.get(NanoHTTPD.QUERY_STRING_PARAMETER));
    }

    protected static Map<String, List<String>> decodeParameters(String queryString) {
        Map<String, List<String>> parms = new HashMap<String, List<String>>();
        if (queryString != null) {
            StringTokenizer st = new StringTokenizer(queryString, "&");
            while (st.hasMoreTokens()) {
                String e = st.nextToken();
                int sep = e.indexOf('=');
                String propertyName = sep >= 0 ? decodePercent(e.substring(0, sep)).trim() : decodePercent(e).trim();
                if (!parms.containsKey(propertyName)) {
                    parms.put(propertyName, new ArrayList<String>());
                }
                String propertyValue = sep >= 0 ? decodePercent(e.substring(sep + 1)) : null;
                if (propertyValue != null) {
                    parms.get(propertyName).add(propertyValue);
                }
            }
        }
        return parms;
    }

    protected static String decodePercent(String str) {
        String decoded = null;
        try {
            decoded = URLDecoder.decode(str, "UTF8");
        } catch (UnsupportedEncodingException ignored) {
            NanoHTTPD.LOG.log(Level.WARNING, "Encoding not supported, ignored", ignored);
        }
        return decoded;
    }

    @SuppressWarnings("static-method")
    protected boolean useGzipWhenAccepted(Response r) {
        return r.getMimeType() != null && r.getMimeType().toLowerCase().contains("text/");
    }

    public final int getListeningPort() {
        return this.myServerSocket == null ? -1 : this.myServerSocket.getLocalPort();
    }

    public final boolean isAlive() {
        return wasStarted() && !this.myServerSocket.isClosed() && this.myThread.isAlive();
    }

    public ServerSocketFactory getServerSocketFactory() {
        return serverSocketFactory;
    }

    public void setServerSocketFactory(ServerSocketFactory serverSocketFactory) {
        this.serverSocketFactory = serverSocketFactory;
    }

    public String getHostname() {
        return hostname;
    }

    public TempFileManagerFactory getTempFileManagerFactory() {
        return tempFileManagerFactory;
    }

    public void makeSecure(SSLServerSocketFactory sslServerSocketFactory, String[] sslProtocols) {
        this.serverSocketFactory = new SecureServerSocketFactory(sslServerSocketFactory, sslProtocols);
    }

    public static Response newChunkedResponse(Response.IStatus status, String mimeType, InputStream data) {
        return new Response(status, mimeType, data, -1);
    }

    public static Response newFixedLengthResponse(Response.IStatus status, String mimeType, InputStream data, long totalBytes) {
        return new Response(status, mimeType, data, totalBytes);
    }

    public static Response newFixedLengthResponse(Response.IStatus status, String mimeType, String txt) {
        ContentType contentType = new ContentType(mimeType);
        if (txt == null) {
            return newFixedLengthResponse(status, mimeType, new ByteArrayInputStream(new byte[0]), 0);
        } else {
            byte[] bytes;
            try {
                CharsetEncoder newEncoder = Charset.forName(contentType.getEncoding()).newEncoder();
                if (!newEncoder.canEncode(txt)) {
                    contentType = contentType.tryUTF8();
                }
                bytes = txt.getBytes(contentType.getEncoding());
            } catch (UnsupportedEncodingException e) {
                NanoHTTPD.LOG.log(Level.SEVERE, "encoding problem, responding nothing", e);
                bytes = new byte[0];
            }
            return newFixedLengthResponse(status, contentType.getContentTypeHeader(), new ByteArrayInputStream(bytes), bytes.length);
        }
    }

    public static Response newFixedLengthResponse(String msg) {
        return newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, msg);
    }

    public Response serve(IHTTPSession session) {
        Map<String, String> files = new HashMap<String, String>();
        Method method = session.getMethod();
        if (Method.PUT.equals(method) || Method.POST.equals(method)) {
            try {
                session.parseBody(files);
            } catch (IOException ioe) {
                return newFixedLengthResponse(Response.Status.INTERNAL_ERROR, NanoHTTPD.MIME_PLAINTEXT, "SERVER INTERNAL ERROR: IOException: " + ioe.getMessage());
            } catch (ResponseException re) {
                return newFixedLengthResponse(re.getStatus(), NanoHTTPD.MIME_PLAINTEXT, re.getMessage());
            }
        }
        Map<String, String> parms = session.getParms();
        parms.put(NanoHTTPD.QUERY_STRING_PARAMETER, session.getQueryParameterString());
        return serve(session.getUri(), method, session.getHeaders(), parms, files);
    }

    @Deprecated
    public Response serve(String uri, Method method, Map<String, String> headers, Map<String, String> parms, Map<String, String> files) {
        return newFixedLengthResponse(Response.Status.NOT_FOUND, NanoHTTPD.MIME_PLAINTEXT, "Not Found");
    }

    public void setAsyncRunner(AsyncRunner asyncRunner) {
        this.asyncRunner = asyncRunner;
    }

    public void setTempFileManagerFactory(TempFileManagerFactory tempFileManagerFactory) {
        this.tempFileManagerFactory = tempFileManagerFactory;
    }

    public void start() throws IOException {
        start(NanoHTTPD.SOCKET_READ_TIMEOUT);
    }

    public void start(final int timeout) throws IOException {
        start(timeout, true);
    }

    public void start(final int timeout, boolean daemon) throws IOException {
        this.myServerSocket = this.getServerSocketFactory().create();
        this.myServerSocket.setReuseAddress(true);
        ServerRunnable serverRunnable = createServerRunnable(timeout);
        this.myThread = new Thread(serverRunnable);
        this.myThread.setDaemon(daemon);
        this.myThread.setName("NanoHttpd Main Listener");
        this.myThread.start();
        while (!serverRunnable.hasBinded && serverRunnable.bindException == null) {
            try {
                Thread.sleep(10L);
            } catch (Throwable e) {
            }
        }
        if (serverRunnable.bindException != null) {
            throw serverRunnable.bindException;
        }
    }

    public void stop() {
        try {
            safeClose(this.myServerSocket);
            this.asyncRunner.closeAll();
            if (this.myThread != null) {
                this.myThread.join();
            }
        } catch (Exception e) {
            NanoHTTPD.LOG.log(Level.SEVERE, "Could not stop all connections", e);
        }
    }

    public final boolean wasStarted() {
        return this.myServerSocket != null && this.myThread != null;
    }
}

