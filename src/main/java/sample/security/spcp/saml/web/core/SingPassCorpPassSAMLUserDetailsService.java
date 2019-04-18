/*
 * Copyright 2019 Vincenzo De Notaris
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

@Service
public class SingPassCorpPassSAMLUserDetailsService implements SAMLUserDetailsService {
	
	// Logger
	private static final Logger LOG = LoggerFactory.getLogger(SingPassCorpPassSAMLUserDetailsService.class);
	
	public Object loadUserBySAML(SAMLCredential credential)
			throws UsernameNotFoundException {
		
		// The method is supposed to identify local account of user referenced by
		// data in the SAML assertion and return UserDetails object describing the user.
		
		// Note that this just demonstrates simple handling for SingPass and CorpPass for understanding purposes
		
		String userID = null;
		if(credential.getAttributes().size() == 1) {
			Attribute attribute = credential.getAttributes().get(0);
			if(attribute.getAttributeValues().size() == 1) {
				XSStringImpl xmlValue = (XSStringImpl) attribute.getAttributeValues().get(0);
				String value = xmlValue.getValue();
				if("UserName".equals(attribute.getName())) {
					// SingPass
					LOG.debug("SingPass Login");
					LOG.debug(value);
					userID = value;
				}
				else
				{
					// CorpPass
					byte[] bytes = Base64.getDecoder().decode(value);
					LOG.debug("CorpPass Login");
					if(LOG.isDebugEnabled()) {
						String xml = new String(bytes, StandardCharsets.UTF_8);
						LOG.debug(xml);
					}
					try {
						
						try(	InputStream rootStartInputStream = new ByteArrayInputStream("<root>".getBytes());
								InputStream dataInputStream = new ByteArrayInputStream(bytes);
								InputStream rootEndInputStream = new ByteArrayInputStream("</root>".getBytes());
								SequenceInputStream xmlInputStream = new SequenceInputStream(Collections.enumeration(Arrays.asList(rootStartInputStream, dataInputStream, rootEndInputStream)))
										) {
					        DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
					        documentFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
					        documentFactory.setIgnoringComments(true);
					        documentFactory.setExpandEntityReferences(false);
					        documentFactory.setNamespaceAware(true);
					        DocumentBuilder documentBuilder = documentFactory.newDocumentBuilder();
					        
							Document corpPassDocument = documentBuilder.parse(xmlInputStream);
							userID = corpPassDocument.getElementsByTagName("CPUID").item(0).getTextContent();
							String uen =  corpPassDocument.getElementsByTagName("CPEntID").item(0).getTextContent();
							if(!uen.equals(attribute.getName())) {
								throw new UsernameNotFoundException("Username not found.");
							}
							
							// Process Auth_Result_Set to add appropriate GrantedAuthorities
						}
					} catch (IOException e) {
						throw new UsernameNotFoundException("Username not found.", e);
					} catch (SAXException e) {
						throw new UsernameNotFoundException("Username not found.", e);
					} catch (ParserConfigurationException e) {
						throw new UsernameNotFoundException("Username not found.", e);
					}
				}
			}
		}
		if(userID == null) {
			throw new UsernameNotFoundException("Username not found.");
		}
		
		LOG.info(userID + " is logged in");
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
		authorities.add(authority);

		// In a real scenario, this implementation has to locate user in a arbitrary
		// dataStore based on information present in the SAMLCredential and
		// returns such a date in a form of application specific UserDetails object.
		return new User(userID, "<abc123>", true, true, true, true, authorities);
	}
	
}
