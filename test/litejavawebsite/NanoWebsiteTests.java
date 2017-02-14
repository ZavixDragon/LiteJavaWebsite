package litejavawebsite;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

public class NanoWebsiteTests {
    private static NanoWebsite website;

    @BeforeClass
    public static void startServer() {
        website = new NanoWebsite(9999, "testsiteresources", "NotFound.html");
        website.start();
    }

    @Test
    public void AskForBasePage_SuppliesIndexHtml() {
        String result = loadContentFromUrlAsString("http://localhost:9999/");

        Assert.assertEquals(loadResourceAsString("Index.html"), result);
    }

    @Test
    public void AskForCustomerBasePage_SuppliesCustomerIndexHtml() {
        String result = loadContentFromUrlAsString("http://localhost:9999/Customer/");

        Assert.assertEquals(loadResourceAsString("customer/Index.html"), result);
    }

    @Test
    public void AskForNonExistentPage_SuppliesNotFoundHtml() {
        String result = loadContentFromUrlAsString("http://localhost:9999/Nowhere");

        Assert.assertEquals(loadResourceAsString("NotFound.html"), result);
    }

    @AfterClass
    public static void stopServer() {
        website.stop();
    }

    private String loadContentFromUrlAsString(String url) {
        return new InputStreamToString(loadContentFromUrl(url)).get();
    }

    private InputStream loadContentFromUrl(String url) {
        try {
            HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
            con.setRequestMethod("GET");
            return con.getInputStream();
        } catch(Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private String loadResourceAsString(String resourceName) {
        try {
            return new String(Files.readAllBytes(Paths.get("").toAbsolutePath().resolve("test").resolve("litejavawebsite").resolve("testsiteresources").resolve(resourceName)), "UTF-8");
        } catch(Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
