package litejavawebsite;

import java.io.IOException;
import java.util.function.Function;

public final class HttpServer extends NanoHTTPD
{
    private Function<IHTTPSession, Response> _serveFunction;

    public HttpServer(final int port)
    {
        super(port);
    }

    public Response serve(IHTTPSession session)
    {
        if (_serveFunction != null)
            return _serveFunction.apply(session);
        return super.serve(session);
    }

    public void start()
    {
        try
        {
            start(SOCKET_READ_TIMEOUT, false);
        }
        catch (IOException e)
        {
            throw new RuntimeException("Unable to start Http server.", e);
        }
    }

    public void setServeFunction(final Function<IHTTPSession, Response> serveFunction)
    {
        _serveFunction = serveFunction;
    }
}

