package com.dreamsecurity.demo.factory;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;

import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

import com.dreamsecurity.demo.policy.CVCertificatePolicy;

public class CVCertificateFactory {

	private CVCertificatePolicy certPolicy;

	public CVCertificateFactory(CVCertificatePolicy cp) {
		this.certPolicy = cp;
	}

	public CVCertificate getInstance(byte[] derEncodedCVCert) {
		
		CVCertificate cert = null;
		
		try {
			CertificateParser.parseCertificate(derEncodedCVCert);			
		} catch (ParseException | ConstructionException e) {
			System.err.println("Error in parsing encoded certificate: " + e.getMessage());
			e.printStackTrace();
		}
		
		return cert;
	}

	public CVCertificate issueCVCert(PrivateKey signingPrivateKey) {

		CVCertificate cert = null;

		try {
			cert = CertificateGenerator.createCertificate(this.certPolicy.getPublicKey(), signingPrivateKey,
					this.certPolicy.getSigningAlgorithm(), this.certPolicy.getCertificationAuthorityReference(),
					this.certPolicy.getCertificateHolderReference(), this.certPolicy.getAuthRole(),
					this.certPolicy.getAccessRights(), this.certPolicy.getValidity().getNotBefore(),
					this.certPolicy.getValidity().getNotAfter(), this.certPolicy.getExtensions(), "BC");
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException
				| ConstructionException | IOException e) {
			System.err.println("Error in creating CVCertificate: " + e.getMessage());
			e.printStackTrace();
		}

		return cert;
	}

	public CVCertificatePolicy getCertPolicy() {
		return certPolicy;
	}

	public void setCertPolicy(CVCertificatePolicy certPolicy) {
		this.certPolicy = certPolicy;
	}

}
