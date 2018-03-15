package com.jnj.honeur.security;

import org.pac4j.core.client.Client;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.exception.HttpAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public final class ForceLoginFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ForceLoginFilter.class);

    private Config config;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        LOGGER.debug("ForceLoginFilter.doFilter");
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;
        final J2EContext context = new J2EContext(request, response);
        final Client client = config.getClients().findClient(request.getParameter(Clients.DEFAULT_CLIENT_NAME_PARAMETER));
        try {
            client.redirect(context);
        } catch (final HttpAction e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    public void destroy() {}

    public Config getConfig() {
        return config;
    }

    public void setConfig(Config config) {
        this.config = config;
    }
}
