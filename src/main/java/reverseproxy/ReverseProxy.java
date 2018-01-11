package reverseproxy;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Formatter;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.cookie.SM;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.cookie.BrowserCompatSpec;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.message.HeaderGroup;
import org.apache.http.protocol.HTTP;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response.IStatus;
import fi.iki.elonen.NanoHTTPD.Response.Status;

/**
 * 
 * Rudolf de Grijs
 *
 * 
 * 
 * Reverse proxy based on NonaHTTPD and Apache HttpComponents
 *
 * 
 * 
 */

public class ReverseProxy extends NanoHTTPD {

	/* Markers for logging */
	private static final Logger LOGGER = LogManager.getLogger(ReverseProxy.class);
	private static final Marker MAIN_MARKER = MarkerManager.getMarker("MAIN");
	private static final Marker CONFIG_MARKER = MarkerManager.getMarker("CONFIG").setParents(MAIN_MARKER);
	private static final Marker PROXY_MARKER = MarkerManager.getMarker("PROXY").setParents(MAIN_MARKER);
	private static final Marker SQL_MARKER = MarkerManager.getMarker("SQL_QUERY").setParents(MAIN_MARKER);

	private final CookieSpec cookieSpec = new BrowserCompatSpec();
	private final RewriteBody rewriteBody = new RewriteBody();
	private final HttpClient proxyClient;
	private final HttpHost targetHost;
	private final ParseCookie parseCookie;

	private int connectTimeout;
	private int readTimeout;
	private String basePath;
	private boolean doForwardIP;
	private String host;
	private URI proxyURI;
	private String targetHostUrl;
	private String targetPath;

	public ReverseProxy(Properties properties) throws IOException {
		super(Integer.parseInt(properties.getProperty("server.port", "80")));
		logConfiguration(properties);
		configureReverseproxy(properties);

		RequestConfig requestConfig = configureProxyClient();
		parseCookie = new ParseCookie();
		proxyClient = HttpClientBuilder.create().setDefaultRequestConfig(requestConfig).build();
		targetHost = HttpHost.create((targetHostUrl.split("://")[1]));

		LOGGER.info(MAIN_MARKER, "Starting reverse proxy server. Listening on port numer {}", getListeningPort());
		start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);
		LOGGER.info(MAIN_MARKER, "Server has been stopped.");

	}

	private void logConfiguration(Properties properties) {

		LOGGER.info(CONFIG_MARKER, "Overzicht configuratie Reverseproxy");
		LOGGER.info(CONFIG_MARKER, "------------------------------------------");
		properties.entrySet().forEach(entry -> {
			LOGGER.info(CONFIG_MARKER, "{}={}", entry.getKey(), entry.getValue());
		});

	}

	private void configureReverseproxy(Properties properties) throws UnknownHostException {

		connectTimeout = Integer.parseInt(properties.getProperty("request.connectionTimeOut", "5"));
		readTimeout = Integer.parseInt(properties.getProperty("request.readTimeOut", "5"));
		doForwardIP = "true".equalsIgnoreCase(properties.getProperty("request.doForwardIP", "true"));
		host = properties.getProperty("host", InetAddress.getLocalHost().getHostName());
		basePath = properties.getProperty("basePath", "/");
		targetHostUrl = properties.getProperty("targetHost", "http://localhost:8080");
		targetPath = properties.getProperty("targetPath", "");
		proxyURI = URI.create(host + basePath);
	}

	private RequestConfig configureProxyClient() {

		RequestConfig.Builder builder = RequestConfig.custom().setRedirectsEnabled(false)

				.setCookieSpec(CookieSpecs.IGNORE_COOKIES).setConnectTimeout(connectTimeout)

				.setSocketTimeout(readTimeout);

		LOGGER.info(CONFIG_MARKER, "RequestConfig has been configured");

		return builder.build();

	}

	public static void main(String[] args) {

		Properties properties = new Properties();
		try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("config.properties")) {
			properties.load(is);
			new ReverseProxy(properties);
		} catch (IOException ioe) {
			LOGGER.error(MAIN_MARKER, "Failed to start the server {}", ioe.getMessage());
		}

	}

	protected HttpRequest newProxyRequestWithEntity(String method, String proxyRequestUri, IHTTPSession session)

			throws IOException {

		HttpEntityEnclosingRequest eProxyRequest = new BasicHttpEntityEnclosingRequest(method, proxyRequestUri);

		eProxyRequest.setEntity(new InputStreamEntity(session.getInputStream()));

		return eProxyRequest;

	}

	@Override

	public Response serve(IHTTPSession session) {

		String uri = session.getUri();
		if (!uri.startsWith(basePath)) {
			return newFixedLengthResponse(Status.NOT_ACCEPTABLE, "text/html", "Request can not be fulfilled");
		}

		String path = uri.substring(basePath.length());
		String query = session.getQueryParameterString();
		String fullQuery = targetHostUrl.toString() + targetPath + encodeUriQuery(path, true)
				+ (query != null ? "?" + encodeUriQuery(query, false) : "");

		try (InputStream is = session.getInputStream()) {
			HttpRequest proxyRequest = null;
			if (session.getHeaders().get(HttpHeaders.CONTENT_LENGTH) != null
					|| session.getHeaders().get(HttpHeaders.TRANSFER_ENCODING) != null) {
				proxyRequest = newProxyRequestWithEntity(session.getMethod().name(), fullQuery, session);
			} else {
				proxyRequest = new BasicHttpRequest(session.getMethod().name(), fullQuery);
			}

			addHeadersRequest(proxyRequest, session.getHeaders());
			HttpResponse proxyResponse = proxyClient.execute(targetHost, proxyRequest);
			IStatus status = getStatus(proxyResponse);
			HttpEntity entity = proxyResponse.getEntity();
			String mimeType = entity.getContentType().getValue();
			long len = entity.getContentLength();

			try (InputStream content = entity.getContent()) {
				InputStream rewrittenContent = rewriteBody.processInputStream(content);
				Response response = (rewrittenContent == null) ? newFixedLengthResponse(status, mimeType, "")
						: newFixedLengthResponse(status, mimeType, rewrittenContent, len);
				Arrays.stream(proxyResponse.getAllHeaders())
						.filter(header -> !responseHeaders.containsHeader(header.getName())).map(header -> {
							String name = header.getName();
							String value = header.getValue();
							Header h = null;
							if ("Set-Cookie".equalsIgnoreCase(name)) {
								org.apache.http.cookie.Cookie cookie = parseCookie.parseCookie(value);
								h = new BasicHeader(name, cookie.toString());
							} else if ("Location".equalsIgnoreCase(name)) {
								if (value.contains(targetHostUrl)) {
									value = value.replace(targetHostUrl, host);
								}

								if (value.contains(targetPath)) {
									value = value.replace(targetPath, path);
								}

								h = new BasicHeader(name, value);
							} else {
								h = header;
							}

							return h;
						}).forEach(header -> {
							response.addHeader(header.getName(), header.getValue());
						});

				return response;

			}

		} catch (Exception e) {
			LOGGER.error(MAIN_MARKER, "Failed to start the server {}", e.getMessage());
			return newFixedLengthResponse(Status.INTERNAL_ERROR, "text/html", e.getMessage());
		}

	}

	private void setXForwardedForHeader(IHTTPSession session, HttpRequest proxyRequest) {

		if (doForwardIP && session.getHeaders().containsKey("remote-addr")) {
			String forHeaderName = "X-Forwarded-For";
			String forHeader = session.getHeaders().get("remote-addr");
			proxyRequest.setHeader(forHeaderName, forHeader);
		}

	}


	private IStatus getStatus(HttpResponse proxyResponse) {
		return new IStatus() {
			StatusLine status = proxyResponse.getStatusLine();

			@Override

			public String getDescription() {
				return status.getReasonPhrase();
			}

			@Override

			public int getRequestStatus() {
				return status.getStatusCode();
			}

		};

	}

	private void addHeadersRequest(HttpRequest proxyRequest, Map<String, String> headers) {

		headers.entrySet().stream().filter(entry -> !hopByHopHeaders.containsHeader(entry.getKey())).forEach(entry -> {
			proxyRequest.addHeader(entry.getKey(), entry.getValue());
		});

	}

	class ParseCookie {

		int port = (proxyURI.getPort() < 0) ? 80 : proxyURI.getPort();
		boolean secure = "https".equals(proxyURI.getScheme());
		CookieOrigin origin = new CookieOrigin(proxyURI.getHost(), port, proxyURI.getPath(), secure);

		org.apache.http.cookie.Cookie parseCookie(String cookieHeader) {
			BasicHeader header = new BasicHeader(SM.SET_COOKIE, cookieHeader);
			try {
				List<org.apache.http.cookie.Cookie> cookies = cookieSpec.parse(header, origin);
				return cookies.get(0);
			} catch (MalformedCookieException e) {
				;
			}

			return null;
		}

	}

	class RewriteBody {

		Pattern replaceUrlContent;
		// =[\\'\\"\\>] + ((targetPath) | (targetUri + targetPath))

		public RewriteBody() {

			replaceUrlContent = Pattern
					.compile("(?:>|=[\\\'\\\"])" + "((" + targetPath + ")|(" + targetHostUrl + targetPath + "))");
		}

		public InputStream processInputStream(InputStream is) {

			try (BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"))) {
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				String line = br.readLine();

				while (line != null) {
					Matcher m = replaceUrlContent.matcher(line);

					if (m.find()) {
						StringBuffer sb = new StringBuffer();
						while (m.find()) {
							if (m.group(1) != null) {
								m.appendReplacement(sb, basePath);
							} else {
								m.appendReplacement(sb, host + basePath);
							}
						}

						m.appendTail(sb);
						bos.write(sb.toString().getBytes(StandardCharsets.UTF_8));
					} else {
						bos.write(line.getBytes(StandardCharsets.UTF_8));
					}

					line = br.readLine();
				}

				new ByteArrayInputStream(bos.toByteArray());
			} catch (Exception e) {
				;
			}

			return null;

		}

	}

	private static CharSequence encodeUriQuery(CharSequence in, boolean encodePercent) {

		// Note that I can't simply use URI.java to encode because it will escape

		// pre-existing escaped things.

		StringBuilder outBuf = null;
		Formatter formatter = null;

		for (int i = 0; i < in.length(); i++) {
			char c = in.charAt(i);

			boolean escape = true;

			if (c < 128) {

				if (asciiQueryChars.get((int) c) && !(encodePercent && c == '%')) {
					escape = false;
				}

			} else if (!Character.isISOControl(c) && !Character.isSpaceChar(c)) {// not-ascii
				escape = false;
			}

			if (!escape) {
				if (outBuf != null)
					outBuf.append(c);
			} else {
				if (outBuf == null) {
					outBuf = new StringBuilder(in.length() + 5 * 3);
					outBuf.append(in, 0, i);
					formatter = new Formatter(outBuf);
				}

				// leading %, 0 padded, width 2, capital hex
				formatter.format("%%%02X", (int) c);// TODO
			}

		}

		return outBuf != null ? outBuf : in;

	}

	private static final BitSet asciiQueryChars;

	static {

		char[] c_unreserved = "_-!.~'()*".toCharArray();// plus alphanum
		char[] c_punct = ",;:$&+=".toCharArray();
		char[] c_reserved = "?/[]@".toCharArray();// plus punct
		asciiQueryChars = new BitSet(128);
		for (char c = 'a'; c <= 'z'; c++)
			asciiQueryChars.set((int) c);
		for (char c = 'A'; c <= 'Z'; c++)
			asciiQueryChars.set((int) c);
		for (char c = '0'; c <= '9'; c++)
			asciiQueryChars.set((int) c);
		for (char c : c_unreserved)
			asciiQueryChars.set((int) c);
		for (char c : c_punct)
			asciiQueryChars.set((int) c);
		for (char c : c_reserved)
			asciiQueryChars.set((int) c);

		asciiQueryChars.set((int) '%');// leave existing percent escapes in place

	}

	private static final HeaderGroup hopByHopHeaders = createHeaderGroup("Connection", "Keep-Alive",
			"Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailers", "Transfer-Encoding", "Upgrade");

	private static final HeaderGroup responseHeaders = createHeaderGroup(HTTP.CONTENT_LEN, HTTP.TRANSFER_ENCODING,
			HTTP.CONN_DIRECTIVE, "Keep-Alive", "TE", "Trailers", "Upgrade");

	private static HeaderGroup createHeaderGroup(String... headerNames) {

		HeaderGroup group = new HeaderGroup();

		for (String header : headerNames) {
			group.addHeader(new BasicHeader(header, null));
		}

		return group;

	}

}