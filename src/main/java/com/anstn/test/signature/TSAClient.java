package com.anstn.test.signature;



import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;



public class TSAClient {
		
		private static final Log LOG = LogFactory.getLog(TSAClient.class);
		private final URL url;
	    private final String username;
	    private final String password;
	    private final MessageDigest digest;
		private X509Certificate cert;
		
	    /**
	     * @param url      the URL of the TSA service
	     * @param username user name of TSA - pass if the tsaURL need sign in
	     * @param password password of TSA - pass if the tsaURL need sign in
	     * @param digest   the message digest to use
	     */
	    TSAClient(URL url, String username, String password, MessageDigest digest, X509Certificate cert) {
	        this.url = url;
	        this.username = username;
	        this.password = password;
	        this.digest = digest;
	        this.cert = cert;
	    }

	    /**
	     * @param messageImprint imprint of message contents
	     * @return the encoded time stamp token
	     * @throws IOException if there was an error with the connection or data from the TSA server,
	     *                     or if the time stamp response could not be validated
	     * @throws OperatorCreationException 
	     * @throws CertificateException 
	     */
	    byte[] getTimeStampToken(byte[] messageImprint) throws IOException, TSPException, CertificateException, OperatorCreationException, NoSuchAlgorithmException {
	        try {
		    	this.digest.reset();
		        byte[] hash = this.digest.digest(messageImprint);

		        // generate cryptographic nonce
		        SecureRandom random = new SecureRandom();
		        int nonce = random.nextInt();

		        // generate TSA request
		        TimeStampRequestGenerator tsaGenerator = new TimeStampRequestGenerator();
		        tsaGenerator.setCertReq(true);
		        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha256.getId());
		        TimeStampRequest request = tsaGenerator.generate(oid, hash, BigInteger.valueOf(nonce));
		       	//request.getEncoded() 이게 TimeStampReq 클래스임.. 
		        // get TSA response
		        byte[] tsaResponse = getTSAResponse(request.getEncoded());   //IOExcetpion

		        TimeStampResponse response = new TimeStampResponse(tsaResponse);   //TSPException
		        response.validate(request);   //TSPException
		        
		        TimeStampToken token = response.getTimeStampToken();
		      
		        //타임스탬프토큰의 검증
		        SigUtils.validateTimestampToken(token, cert);  //CertificateException, OperatorCreationException
		   
		        if (token == null) {
		        	LOG.error("Response does not have a time stamp token");
		            throw new IOException("Response does not have a time stamp token");
		        }

		        return token.getEncoded();
	        } catch (IOException e) {
	        	LOG.error("error occur while communication with TSA_SERVER");
	        	throw e; 
	        } catch (TSPException e) {
	        	LOG.error("inappropriate TSA response");
	        	throw e; 
	        } catch (OperatorCreationException | CertificateException e) {
	        	LOG.error("error occur while validating token because cert problem");
	        	throw e;
	        }

	    }

	    private byte[] getTSAResponse(byte[] request) throws IOException  {
	    	LOG.debug("Opening connection to TSA server");
	    	HttpURLConnection connection = (HttpURLConnection) url.openConnection();
	    	connection.setDoOutput(true); // output을 사용하도록 설정 (default : false)
	    	connection.setDoInput(true); // input을 사용하도록 설정 (default : true)
	    	connection.setRequestMethod("POST"); // 요청 방식을 설정 (default : GET)
	    	connection.setRequestProperty("Content-type", "application/json; charset=UTF-8");
	    	connection.setConnectTimeout(60); // 타임아웃 시간 설정 (default : 무한대기)


	    	LOG.debug("Established connection to TSA server");

//	        if (Strings.isNotBlank(this.username) && Strings.isNotBlank(this.password)) {
//	            connection.setRequestProperty(this.username, this.password);
//	        }

	        // read response
	        OutputStream output = null;
	        try {
	            output = connection.getOutputStream(); //OutputStream에 전달할 data 쓰기 . 
	            output.write(request);
	        } finally {
	            IOUtils.closeQuietly(output);
	        }
	        LOG.debug("Waiting for response from TSA server");

	        InputStream input = null;
	        byte[] response;
	        try {
	            input = connection.getInputStream(); //응답결과 받아오기 
	            response = IOUtils.toByteArray(input); //응답받은걸 바이트배열로 변환 
	        } finally {
	            IOUtils.closeQuietly(input);
	        }

	        LOG.debug("Received response from TSA server");
	        return response;
	    }
}
