package litejavawebsite;

public class NanoWebsite {
    private final HttpServer server;
    private final UriResourceMap map;

    public NanoWebsite(UriResources... uriResources) {
        server = new HttpServer(9999);
        map = new UriResourceMap(uriResources);
        server.setServeFunction(this::serve);
    }

    public void start() {
        server.start();
    }

    private NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
        String uri = session.getUri();
        System.out.println(uri);
        int extensionIndex = uri.lastIndexOf('.');
        if (extensionIndex == -1) {
            String main = new Resource("../site/main.html").toString().replace("var resources = [];", String.format("var resources = [ \"%s\" ];", String.join("\", \"", map.get(uri))));
            return new StringResponse(new MimeType(new FileExtension("html")), main).get();
        }
        return new ContentResponse(new MimeType(new FileExtension(uri)), new Resource("../site" + uri)).get();
    }
}
