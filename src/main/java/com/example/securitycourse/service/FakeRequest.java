package com.example.securitycourse.service;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletConnection;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpUpgradeHandler;
import jakarta.servlet.http.Part;

import java.io.BufferedReader;
import java.io.IOException;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;

/**
 * Минимальная заглушка HttpServletRequest для использования в DemoDataService —
 * чтобы AuditService мог взять IP и User-Agent оттуда.
 * Все остальные методы возвращают null/пустые значения.
 */
public class FakeRequest implements HttpServletRequest {

    private final String remoteAddr;
    private final String userAgent;

    public FakeRequest(String remoteAddr, String userAgent) {
        this.remoteAddr = remoteAddr;
        this.userAgent = userAgent;
    }

    @Override public String getRemoteAddr() { return remoteAddr; }

    @Override public String getHeader(String name) {
        if ("User-Agent".equalsIgnoreCase(name)) return userAgent;
        return null;
    }

    // Все остальные методы — заглушки

    @Override public String getAuthType() { return null; }
    @Override public Cookie[] getCookies() { return new Cookie[0]; }
    @Override public long getDateHeader(String s) { return 0; }
    @Override public Enumeration<String> getHeaders(String s) { return Collections.emptyEnumeration(); }
    @Override public Enumeration<String> getHeaderNames() { return Collections.emptyEnumeration(); }
    @Override public int getIntHeader(String s) { return 0; }
    @Override public String getMethod() { return "GET"; }
    @Override public String getPathInfo() { return null; }
    @Override public String getPathTranslated() { return null; }
    @Override public String getContextPath() { return ""; }
    @Override public String getQueryString() { return null; }
    @Override public String getRemoteUser() { return null; }
    @Override public boolean isUserInRole(String s) { return false; }
    @Override public Principal getUserPrincipal() { return null; }
    @Override public String getRequestedSessionId() { return null; }
    @Override public String getRequestURI() { return "/"; }
    @Override public StringBuffer getRequestURL() { return new StringBuffer("http://localhost/"); }
    @Override public String getServletPath() { return ""; }
    @Override public HttpSession getSession(boolean b) { return null; }
    @Override public HttpSession getSession() { return null; }
    @Override public String changeSessionId() { return null; }
    @Override public boolean isRequestedSessionIdValid() { return false; }
    @Override public boolean isRequestedSessionIdFromCookie() { return false; }
    @Override public boolean isRequestedSessionIdFromURL() { return false; }
    @Override public boolean authenticate(HttpServletResponse r) { return false; }
    @Override public void login(String s, String s1) { }
    @Override public void logout() { }
    @Override public Collection<Part> getParts() { return Collections.emptyList(); }
    @Override public Part getPart(String s) { return null; }
    @Override public <T extends HttpUpgradeHandler> T upgrade(Class<T> aClass) { return null; }

    @Override public Object getAttribute(String s) { return null; }
    @Override public Enumeration<String> getAttributeNames() { return Collections.emptyEnumeration(); }
    @Override public String getCharacterEncoding() { return "UTF-8"; }
    @Override public void setCharacterEncoding(String s) { }
    @Override public int getContentLength() { return 0; }
    @Override public long getContentLengthLong() { return 0; }
    @Override public String getContentType() { return null; }
    @Override public ServletInputStream getInputStream() { return null; }
    @Override public String getParameter(String s) { return null; }
    @Override public Enumeration<String> getParameterNames() { return Collections.emptyEnumeration(); }
    @Override public String[] getParameterValues(String s) { return new String[0]; }
    @Override public Map<String, String[]> getParameterMap() { return Collections.emptyMap(); }
    @Override public String getProtocol() { return "HTTP/1.1"; }
    @Override public String getScheme() { return "http"; }
    @Override public String getServerName() { return "localhost"; }
    @Override public int getServerPort() { return 8080; }
    @Override public BufferedReader getReader() { return null; }
    @Override public String getRemoteHost() { return remoteAddr; }
    @Override public void setAttribute(String s, Object o) { }
    @Override public void removeAttribute(String s) { }
    @Override public Locale getLocale() { return Locale.getDefault(); }
    @Override public Enumeration<Locale> getLocales() { return Collections.enumeration(Collections.singletonList(Locale.getDefault())); }
    @Override public boolean isSecure() { return false; }
    @Override public RequestDispatcher getRequestDispatcher(String s) { return null; }
    @Override public int getRemotePort() { return 0; }
    @Override public String getLocalName() { return "localhost"; }
    @Override public String getLocalAddr() { return "127.0.0.1"; }
    @Override public int getLocalPort() { return 8080; }
    @Override public ServletContext getServletContext() { return null; }
    @Override public AsyncContext startAsync() { return null; }
    @Override public AsyncContext startAsync(ServletRequest r, ServletResponse re) { return null; }
    @Override public boolean isAsyncStarted() { return false; }
    @Override public boolean isAsyncSupported() { return false; }
    @Override public AsyncContext getAsyncContext() { return null; }
    @Override public DispatcherType getDispatcherType() { return DispatcherType.REQUEST; }
    @Override public String getRequestId() { return ""; }
    @Override public String getProtocolRequestId() { return ""; }
    @Override public ServletConnection getServletConnection() { return null; }
}