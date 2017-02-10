package litejavawebsite;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

public class NanoWebsiteTests {
    private static NanoWebsite website;

    @BeforeClass
    public static void startServer() {
        website = new NanoWebsite(9999, "testsiteresources");
        website.start();
    }

    @Test
    public void AskForBasePage_SuppliesIndexHtml() {
        String result = loadContentFromUrl("http://localhost:9999/");

        Assert.assertEquals(loadResource("Index.html"), result);
    }

    @Test
    public void AskForCustomerBasePage_SuppliesCustomerIndexHtml() {
        String result = loadContentFromUrl("http://localhost:9999/Customer/");

        Assert.assertEquals(loadResource("customer/Index.html"), result);
    }

    @Test
    public void AskForLoginPage_SuppliesLoginHtml() {
        String result = loadContentFromUrl("http://localhost:9999/Login");

        Assert.assertEquals(loadResource("Login.html"), result);
    }

    @AfterClass
    public static void stopServer() {
        website.stop();
    }

    private String loadContentFromUrl(String url) {
        try {
            HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
            con.setRequestMethod("GET");
            return new InputStreamToString(con.getInputStream()).get();
        } catch(Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private String loadResource(String resourceName) {
        try {
            return new String(Files.readAllBytes(Paths.get("").toAbsolutePath().resolve("test").resolve("litejavawebsite").resolve("testsiteresources").resolve(resourceName)), "UTF-8");
        } catch(Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
