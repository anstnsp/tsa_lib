package com.finger.tsa.signature;


import java.io.IOException;
import java.security.GeneralSecurityException;
import org.apache.http.client.ClientProtocolException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;

import com.finger.tsa.exception.ConException;
import com.finger.tsa.exception.DAppException;
import com.finger.tsa.exception.NoSignerException;
import com.finger.tsa.exception.NoTimeStampException;


public class Test {

	public static void main(String[] args) throws NullPointerException, OperatorCreationException, IOException, CMSException, TSPException, ConException, NoTimeStampException, GeneralSecurityException, DAppException, NoSignerException {

		String pubKeyPath = "./tsa_cert.der";  
		String privKeyPath = "./tsa_cert.key";
		//토큰 발급 url
		String tsaUrl = "http://localhost:9002";
		//HttpConnectionConfig con = null;
		
		SignatureService service = new SignatureService(privKeyPath, pubKeyPath, tsaUrl);

		System.out.println(service.makeFileAndInsertBC("./aa.pdf", "./",  "gooood333.pdf"));
		//String result = service.verifySigFile("./gooood333.pdf");
		//System.out.println("조회결과:"+ result);

	}

}



//NullPointerException, 
//OperatorCreationException, 
//IOException, 
//CMSException, 
//TSPException, 
//ConException, 
//NoTimeStampException, 
//GeneralSecurityException, 
//DAppException