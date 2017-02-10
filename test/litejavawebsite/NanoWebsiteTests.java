package litejavawebsite;

import org.junit.Assert;
import org.junit.Test;

import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

public class NanoWebsiteTests {
    @Test
    public void Gold() {
        NanoWebsite site = new NanoWebsite(9999, "../../test/litejavawebsite/testsiteresources");
        site.start();

        byte[] result = loadContentFromUrl("http://localhost:9999/");

        Assert.assertEquals(loadResource("index.html"), result);
    }

    private byte[] loadContentFromUrl(String url) {
        try {
            HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
            con.setRequestMethod("GET");
            return new InputStreamToBytes(con.getInputStream()).get();
        } catch(Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private byte[] loadResource(String resourceName) {
        try {
            return Arrays.copyOf(Files.readAllBytes(Paths.get("").toAbsolutePath().resolve("test").resolve("litejavawebsite").resolve("testsiteresources").resolve(resourceName)), 1024);
        } catch(Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
