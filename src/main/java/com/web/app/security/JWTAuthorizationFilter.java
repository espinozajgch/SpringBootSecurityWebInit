package com.web.app.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

import static com.web.app.security.Constants.HEADER_AUTHORIZACION_KEY;
import static com.web.app.security.Constants.TOKEN_BEARER_PREFIX;
import static com.web.app.security.Constants.SUPER_SECRET_KEY;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private static final Logger LOGGER = LoggerFactory.getLogger(JWTAuthorizationFilter.class);

	public JWTAuthorizationFilter(AuthenticationManager authManager) {
		super(authManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		try {
			String header = req.getHeader(HEADER_AUTHORIZACION_KEY);
			if (header == null || !header.startsWith(TOKEN_BEARER_PREFIX)) {
				chain.doFilter(req, res);
				return;
			}
			UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
			SecurityContextHolder.getContext().setAuthentication(authentication);
			chain.doFilter(req, res);
		} catch (AuthenticationException ae) {
			LOGGER.error(" Bad credentials");
		}
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(HEADER_AUTHORIZACION_KEY);

		if (token != null) {
			try {
				// Se procesa el token y se recupera el usuario.
				String user = Jwts.parser()
						.setSigningKey(SUPER_SECRET_KEY)
						.parseClaimsJws(token.replace(TOKEN_BEARER_PREFIX, ""))
						.getBody()
						.getSubject();

				if (user != null) {
					return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
				}
				return null;
			} catch (ExpiredJwtException e) {
				LOGGER.debug(" Token expired ");
			} catch (SignatureException e) {
				LOGGER.error(e.getMessage());
			} catch(Exception e){
				LOGGER.error(" Some other exception in JWT parsing ");
			}


		}
		return null;
	}
}