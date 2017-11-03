package io.salte.examples.openidconnect.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import java.util.List;
import java.util.Collections;

@EnableWebSecurity
@PropertySource("classpath:oauth2-clients.properties")
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	private Environment environment;

	public SecurityConfig(Environment environment) {
		this.environment = environment;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
        OAuth2LoginConfigurer<HttpSecurity> o = http.authorizeRequests().anyRequest().authenticated().and().oauth2Login();
        o.
	    .clients(clientRegistrationRepository());
	}

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
		List<ClientRegistration> clientRegistrations = Collections.singletonList(
			clientRegistration("security.oauth2.client.registrations.google."));

		return new InMemoryClientRegistrationRepository(clientRegistrations);
	}

	private ClientRegistration clientRegistration(String clientPropertyKey) {
		String registrationId = this.environment.getProperty(clientPropertyKey + "registration-id");
		String clientId = this.environment.getProperty(clientPropertyKey + "client-id");
		String clientSecret = this.environment.getProperty(clientPropertyKey + "client-secret");
		ClientAuthenticationMethod clientAuthenticationMethod = new ClientAuthenticationMethod(
			this.environment.getProperty(clientPropertyKey + "client-authentication-method"));
		AuthorizationGrantType authorizationGrantType = AuthorizationGrantType.valueOf(
			this.environment.getProperty(clientPropertyKey + "authorized-grant-type").toUpperCase());
		String redirectUri = this.environment.getProperty(clientPropertyKey + "redirect-uri");
		String[] scope = this.environment.getProperty(clientPropertyKey + "scope").split(",");
		String authorizationUri = this.environment.getProperty(clientPropertyKey + "authorization-uri");
		String tokenUri = this.environment.getProperty(clientPropertyKey + "token-uri");
		String userInfoUri = this.environment.getProperty(clientPropertyKey + "user-info-uri");
		String jwkSetUri = this.environment.getProperty(clientPropertyKey + "jwk-set-uri");
		String clientName = this.environment.getProperty(clientPropertyKey + "client-name");

		return new ClientRegistration.Builder(registrationId)
			.clientId(clientId)
			.clientSecret(clientSecret)
			.clientAuthenticationMethod(clientAuthenticationMethod)
			.authorizedGrantType(authorizationGrantType)
			.redirectUri(redirectUri)
			.scope(scope)
			.authorizationUri(authorizationUri)
			.tokenUri(tokenUri)
			.userInfoUri(userInfoUri)
			.jwkSetUri(jwkSetUri)
			.clientName(clientName)
			.build();
	}
}
