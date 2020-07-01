package com.finger.tsa.signature;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import com.finger.tsa.dto.RequestDto;
import com.finger.tsa.exception.ConException;
import com.finger.tsa.exception.DAppException;
import com.finger.tsa.exception.NoSignerException;
import com.finger.tsa.exception.NoTimeStampException;
import com.finger.tsa.response.CommonResult;
import com.finger.tsa.util.HttpConnectionConfig;
import com.finger.tsa.util.Util;
import com.google.gson.Gson;



public class SignatureService {
	private static final Log LOG = LogFactory.getLog(SignatureService.class);
	private final SigningService signingService;
	private final String tsaUrl; 


	/**
	 * 
	 * @param privKeyPath - 개인키 위치 경로
	 * @param pubKeyPath - 인증서 위치 경로
	 * @param tsaUrl - tsa서버 url 
	 */
	public SignatureService(String privKeyPath, String pubKeyPath, String tsaUrl) {
	
		this.signingService = new SigningService(privKeyPath, pubKeyPath, tsaUrl);
		this.tsaUrl = tsaUrl;
		
	}
	

	/**
	 * 
	 * @param originFilePathAndNm - 서명할PDF파일의 파일명포함경로
	 * @param makeFilePath - 서명된파일이 생성될 위치
	 * @param makeFileName - 서명된파일의 이름
	 * @return true
	 * @throws IOException
	 * @throws NullPointerException
	 * @throws OperatorCreationException
	 * @throws CMSException
	 * @throws TSPException
	 * @throws ConException
	 * @throws NoTimeStampException
	 * @throws GeneralSecurityException
	 * @throws DAppException
	 * @throws NoSignerException 
	 */
	public boolean makeFileAndInsertBC(String originFilePathAndNm, String makeFilePath, String makeFileName) throws IOException, NullPointerException, OperatorCreationException, CMSException, TSPException,ConException, NoTimeStampException, GeneralSecurityException, DAppException, NoSignerException {
		String makeFileFullPath = makeFilePath+makeFileName;
		try {
	       	File originFile = new File(originFilePathAndNm); //원본PDF의 파일
	    	byte[] originfileByte = Files.readAllBytes(originFile.toPath()); //원본파일을 바이트배열로 변환. 

			//1.TSA서버에게 요청하여 토큰 받고 서명이 된 byte[]문서 리턴. 
			byte[] signedPdfByte = signingService.signPdf(originfileByte);
			//2.서명파일 만들기. 
	    	Util.byteArrayToFile(signedPdfByte, makeFilePath, makeFileName);
	    	//3.서명된 PDF파일을 hash하여 블록체인에 등록 하고 응답받음. 
	    	boolean result = signingService.toBlcokChain(originfileByte, signedPdfByte, makeFileFullPath);
	    	return result;
		} catch (NullPointerException e) {
			File file = new File(makeFileFullPath); 
    		file.delete(); 
    		throw e;
		} catch (IOException e) {
			File file = new File(makeFileFullPath); 
    		file.delete(); 
    		throw e;
		} catch (GeneralSecurityException e) {
			File file = new File(makeFileFullPath); 
    		file.delete(); 
    		throw e;
		}

	}

	/**
	 * @see 블록체인 상 해당 파일이 존재하는지 조회
	 * @param filePath - 서명된 파일
	 * @return 조회 결과 값  
	 * @throws IOException
	 * @throws OperatorCreationException
	 * @throws CMSException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws ConException
	 * @throws TSPException
	 * @throws DAppException
	 */
	@SuppressWarnings("static-access")
	public String verifySigFile(String filePath) throws IOException, OperatorCreationException, CMSException, CertificateException, NoSuchAlgorithmException, ConException, TSPException, DAppException {
    	//2.입력받은 경로의 파일(토큰삽입된파일)을 읽어다가 타임스탬프토큰 추출
    	File signedFile = new File(filePath);
    	PDDocument doc = null;
    	TimeStampToken timeStampToken = null;
    	ByteArrayInputStream certStream = null;
    	
    	try {
        	byte[] signedFileByte = Files.readAllBytes(signedFile.toPath()); //IOException
        	String signedPDFHshed = Util.getHashFromByteArray(signedFileByte); //토큰삽입된 문서 해쉬 
        	
        	for(PDSignature sig : doc.load(signedFileByte).getSignatureDictionaries()) {
     		    COSDictionary sigDict = sig.getCOSObject();
                COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);
           
                byte[] byteArray =   sig.getSignedContent(signedFileByte);
                CMSProcessable signedContent = new CMSProcessableByteArray(byteArray);
               
                byte[] certData = contents.getBytes();
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                certStream = new ByteArrayInputStream(certData);
		        CMSSignedData signedData = new CMSSignedData(signedContent, contents.getBytes());
		        Collection<? extends Certificate> certs = factory.generateCertificates(certStream);
    		    X509Certificate cert = null;
    	           for( Certificate tempCert : certs) {
    	        	   if(SigUtils.checkTimeStampCertificateUsage((X509Certificate)tempCert) == false) {
    	        		   throw new Error("Certificate extended key usage does not include timeStamping");
    	        	   }
    	        	   cert = (X509Certificate) tempCert;
    	           }
    	  		   Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
    		       if (signers.isEmpty()) {
    		            throw new IOException("No signers in signature");
    		       }
    		       SignerInformation signerInformation = signers.iterator().next();
    		       timeStampToken = SigUtils.extractTimeStampTokenFromSignerInformation(signerInformation); //토큰추출.
    		        
    		       //타임스탬프토큰의 유효성 체크
    		       if(timeStampToken != null)  SigUtils.validateTimestampToken(timeStampToken, cert);
     		} //for end 
 
     	//전송하기 위해 타임스탬프토큰 base64인코딩 
     	String tokenEncodedString = Util.encodeBase64String(timeStampToken.getEncoded());
    	//3.추출한 토큰과 경로상받은 파일을 블록체인댑에게 보냄. 
     	RequestDto reqDto = new RequestDto(tokenEncodedString, signedPDFHshed);
    	
     	HttpConnectionConfig.getHttpClient();
     	HttpResponse tsaResp = HttpConnectionConfig.doPost(tsaUrl + "/" + "verify", reqDto);

     	String resBody = new BasicResponseHandler().handleResponse(tsaResp);
     	Gson gson = new Gson(); 
     	CommonResult result = gson.fromJson(resBody, CommonResult.class); 

     	if(result.getCode() != 0) {
     		LOG.error("TSA_RESPONSE : " + resBody.toString());
     		throw new DAppException("TSA Server error");
     	}
     	
    	return resBody;

		} catch (OperatorCreationException e) {
			LOG.error("Exception position : SigUtils.validateTimestampToken(timeStampToken, cert), msg:"+e.getMessage());
			throw e;
		} catch (CMSException e) {
			LOG.error("Exception position : new CMSSignedData(signedContent, contents.getBytes()), msg:"+e.getMessage());
			throw e;
		} catch (CertificateException e) {
			LOG.error("Exception position : CertificateFactory.getInstance(X.509), msg:"+e.getMessage());
			throw e;
		} catch (IOException e) {
			LOG.error("Exception position : sig.getSignedContent(signedPdf), msg:"+e.getMessage());
			throw e;
		} catch (NoSuchAlgorithmException e) {
			LOG.error("Exception position : Util.getHashFromByteArray(fileContent), msg"+e.getMessage());
			throw e;
		}catch (TSPException e) {
			LOG.error("Exception position : SigUtils.extractTimeStampTokenFromSignerInformation(signerInformation)"
					+ "| SigUtils.validateTimestampToken(timeStampToken, cert), msg:"+e.getMessage());
			throw e;
		} finally {
	    	if(doc != null) try { doc.close();} catch(IOException e) { 
	    		LOG.error("doc.close(), msg:"+e.getMessage()); 
	    		throw e;
	    	}
	    	if(certStream != null) try { certStream.close();} catch(IOException e) { 
	    		LOG.error("certStream.close(), msg:"+e.getMessage()); 
	    		throw e;
	    	}
    	}

	}


}
