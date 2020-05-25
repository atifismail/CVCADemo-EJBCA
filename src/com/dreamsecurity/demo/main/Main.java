package com.dreamsecurity.demo.main;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.asn1.eac.CVCertificateRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.HolderReferenceField;

import com.dreamsecurity.demo.core.Validity;
import com.dreamsecurity.demo.factory.CVCertificateFactory;
import com.dreamsecurity.demo.factory.CVRequestFactory;
import com.dreamsecurity.demo.policy.CVCertificatePolicy;
import com.dreamsecurity.demo.util.Constants.ValidityType;

public class Main {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {

		Security.addProvider(new BouncyCastleProvider());

		// Create new key pair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
		keyGen.initialize(2048, new SecureRandom());

		KeyPair cvcaKeyPair = keyGen.generateKeyPair();
		KeyPair dvKeyPair = keyGen.generateKeyPair();
		KeyPair isKeyPair = keyGen.generateKeyPair();
		KeyPair reqKeyPair = keyGen.generateKeyPair();

		// cvca
		CVCertificate cvca = issueCert(cvcaKeyPair.getPublic(), new HolderReferenceField("KR", "CVCA", "00001"),
				new CAReferenceField("KR", "CVCA", "00001"), AuthorizationRoleEnum.CVCA, cvcaKeyPair.getPrivate());

		// domestic dvca
		CVCertificate dvca_d = issueCert(dvKeyPair.getPublic(), new HolderReferenceField("KR", "DVCA", "00001"),
				new CAReferenceField("KR", "CVCA", "00001"), AuthorizationRoleEnum.DV_D, cvcaKeyPair.getPrivate());

		// foreign dvca
		CVCertificate dvca_f = issueCert(dvKeyPair.getPublic(), new HolderReferenceField("KR", "DVCA", "00001"),
				new CAReferenceField("KR", "CVCA", "00001"), AuthorizationRoleEnum.DV_F, cvcaKeyPair.getPrivate());

		// is
		CVCertificate is = issueCert(isKeyPair.getPublic(), new HolderReferenceField("KR", "IS01", "00001"),
				new CAReferenceField("KR", "DVCA", "00001"), AuthorizationRoleEnum.IS, dvKeyPair.getPrivate());

		// cert request
		CVCAuthenticatedRequest req = issueCertRequest(new HolderReferenceField("KR", "DVCA", "00001"), reqKeyPair, 
				new CAReferenceField("KR", "CVCA", "00001"), cvcaKeyPair);
	}

	public static CVCertificate issueCert(PublicKey pubKey, HolderReferenceField holdId, CAReferenceField authId,
			AuthorizationRoleEnum role, PrivateKey signingKey) {

		CVCertificatePolicy cp = new CVCertificatePolicy();

		cp.setCertificateHolderReference(holdId.getCountry(), holdId.getMnemonic(), holdId.getSequence());
		cp.setCertificationAuthorityReference(authId.getCountry(), authId.getMnemonic(), authId.getSequence());
		cp.setPublicKey(pubKey);
		cp.setAuthRole(role);
		cp.setAccessRights(AccessRightEnum.READ_ACCESS_DG3_AND_DG4);
		cp.setSigningAlgorithm("SHA256withRSA");
		cp.setValidity(new Validity(ValidityType.YEAR, 1));
		cp.setExtension("1.2.3.4.5.6", "test".getBytes());

		CVCertificateFactory f = new CVCertificateFactory(cp);

		CVCertificate cert = f.issueCVCert(signingKey);

		System.out.println(cert);

		return cert;
	}
	
	public static CVCAuthenticatedRequest issueCertRequest(HolderReferenceField holderRef, KeyPair holderKeyPair, CAReferenceField authORpreviousHolderRef,
			KeyPair authORPreviousKeyPair) {
		
		CVRequestFactory f = new CVRequestFactory();
		
		CVCAuthenticatedRequest req =  f.issueCVCertRequest(holderRef, holderKeyPair, "SHA256withRSA", authORpreviousHolderRef, authORPreviousKeyPair);
		
		System.out.println(req);
		
		return req;
		
	}

}
