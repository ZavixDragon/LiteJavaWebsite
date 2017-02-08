package litejavawebsite;

public class WebsiteServer {
    private final HttpServer server;

    public WebsiteServer(int port) {
        server = new HttpServer(port);
        server.setServeFunction(this::serve);
    }

    public void start() {
        server.start();
    }

    private NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
        String uri = session.getUri();
        System.out.println(uri);
        if (uri.equals("/"))
            uri = "/HelloWorld";
        int extensionIndex = uri.lastIndexOf('.');
        if (extensionIndex == -1) {
            String main = new Resource("../site/main.html").toString().replace("<body onload=\"loadPage()\">", String.format("<body onload=\"loadPage('%s')\">", uri.substring(1)));
            return new StringResponse(new MimeType(new FileExtension("html")), main).get();
        }
        return new ContentResponse(new MimeType(new FileExtension(uri)), new Resource("../site/" + uri)).get();
    }
}
