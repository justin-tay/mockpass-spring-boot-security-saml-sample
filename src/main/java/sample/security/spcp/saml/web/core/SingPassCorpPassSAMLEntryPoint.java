/*
 * Copyright 2019 Justin Tay
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample.security.spcp.saml.web.core;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.common.SAMLException;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Sample SingPass/CorpPass SAML Entry Point
 * 
 * @author Justin Tay
 *
 */
public class SingPassCorpPassSAMLEntryPoint extends SAMLEntryPoint {
    protected static final Logger LOG = LoggerFactory.getLogger(SingPassCorpPassSAMLEntryPoint.class);

	@Override
	protected void initializeSSO(SAMLMessageContext context, AuthenticationException e)
			throws MetadataProviderException, SAMLException, MessageEncodingException {
		HTTPOutTransport httpOutTransport = (HTTPOutTransport) context.getOutboundMessageTransport();
		HttpServletRequestAdapter httpInTransport = (HttpServletRequestAdapter) context.getInboundMessageTransport();
		List<Endpoint> endpoints = context.getPeerEntityRoleMetadata()
				.getEndpoints(SingleSignOnService.DEFAULT_ELEMENT_NAME);
		Endpoint endpoint = endpoints.get(0);
		String partnerId = context.getLocalEntityId();
		HttpServletRequest request = httpInTransport.getWrappedRequest();
		String target = request.getRequestURL().toString();
		String queryString = request.getQueryString();
		if (queryString != null) {
			target = target + "?" + queryString;
		}
		String singleSignOnUri = createSingleSignOnUri(endpoint.getLocation(), partnerId, target, null);
		LOG.debug("Redirecting to SingleSignOnService {}", singleSignOnUri);
		httpOutTransport.sendRedirect(singleSignOnUri);
	}
	
	public static String createSingleSignOnUri(String singleSignOnServiceLocation, String partnerId, String target, String eServiceId) {
		Map<String, String> uriVariables = new HashMap<String, String>();
		uriVariables.put("RequestBinding", "HTTPArtifact");
		uriVariables.put("ResponseBinding", "HTTPArtifact");
		uriVariables.put("PartnerId", partnerId);
		uriVariables.put("Target", target);
		uriVariables.put("NameIdFormat", "Email");
		uriVariables.put("esrvcID", eServiceId);
		
		
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpUrl(singleSignOnServiceLocation)
			    .queryParam("RequestBinding", "{RequestBinding}")
			    .queryParam("ResponseBinding", "{ResponseBinding}")
			    .queryParam("PartnerId", "{PartnerId}")
			    .queryParam("Target", "{Target}")
			    .queryParam("NameIdFormat","{NameIdFormat}");
		if(eServiceId != null) {
			uriComponentsBuilder.queryParam("esrvcID", "{esrvcID}");
		}
		
		return uriComponentsBuilder.encode().buildAndExpand(uriVariables).toUri().toString();
	}
}
