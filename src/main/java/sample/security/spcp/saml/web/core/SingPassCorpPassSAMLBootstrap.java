package sample.security.spcp.saml.web.core;

import org.opensaml.Configuration;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.saml.SAMLBootstrap;

/**
 * Initialization for SAML library.
 * 
 * Sets safer defaults for security configuration.
 * 
 * @author Justin Tay
 *
 */
public class SingPassCorpPassSAMLBootstrap extends SAMLBootstrap {
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
	    super.postProcessBeanFactory(beanFactory);
	    BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();

		/**
		 * Ensure safer configuration. For instance signature and digest algorithms are
		 * by default using SHA1 set in DefaultSecurityConfigurationBootstrap and that
		 * is no longer acceptable for signatures and hash only applications as the
		 * security strength is less than 80 bits.
		 * 
		 * @see https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
		 * @see https://www.w3.org/TR/xmlenc-core1/
		 */
        // Asymmetric key algorithms
	    config.registerSignatureAlgorithmURI("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        config.deregisterSignatureAlgorithmURI("DSA");
        config.registerSignatureAlgorithmURI("EC", SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA256);
        
        // HMAC algorithms
        config.registerSignatureAlgorithmURI("AES", SignatureConstants.ALGO_ID_MAC_HMAC_SHA256);
        config.deregisterSignatureAlgorithmURI("DESede");
        
        // Other signature-related params
	    config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
	    
        // Data encryption URI's
	    config.deregisterDataEncryptionAlgorithmURI("DESede", 168);
	    config.deregisterDataEncryptionAlgorithmURI("DESede", 192);
	    
        // Key encryption URI's
        
        // Asymmetric key transport algorithms
        config.deregisterKeyTransportEncryptionAlgorithmURI("RSA", null, "DESede");
        
        // Symmetric key wrap algorithms
        config.deregisterKeyTransportEncryptionAlgorithmURI("DESede", 168, null);
        config.deregisterKeyTransportEncryptionAlgorithmURI("DESede", 192, null);
	}
}
