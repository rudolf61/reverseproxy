package reverseproxy.proxy;

import java.util.Properties;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

public interface Proxy {

	void configure(Properties properties);
	Response executeRequest(IHTTPSession session);
	
}
