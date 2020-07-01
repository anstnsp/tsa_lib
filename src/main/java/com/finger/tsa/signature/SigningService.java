package com.finger.tsa.signature;
import org.apache.commons.io.FileUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.json.simple.JSONObject;

import com.finger.tsa.exception.ConException;
import com.finger.tsa.exception.DAppException;
import com.finger.tsa.exception.NoSignerException;
import com.finger.tsa.exception.NoTimeStampException;
import com.finger.tsa.response.CommonResult;
import com.finger.tsa.util.HttpConnectionConfig;
import com.finger.tsa.util.Util;
import com.google.gson.Gson;

import java.io.*;
import java.nio.file.Files;

import java.security.GeneralSecurityException;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import java.security.cert.X509Certificate;

import java.util.Calendar;
import java.util.Collection;



public class SigningService {
		private static final Log LOG = LogFactory.getLog(SigningService.class);
		
	    private final String privKeyPath;
	    private final String pubKeyPath;
	    private final String tsaUrl;
	    private HttpConnectionConfig connection; 
	    
	    public SigningService(String privKeyPath, String pubKeyPath, String tsaUrl) {
	        this.privKeyPath = privKeyPath;
	        this.pubKeyPath = pubKeyPath;
	        this.tsaUrl = tsaUrl;
	    }

	    public byte[] signPdf(byte[] pdfToSign) throws NullPointerException, GeneralSecurityException, IOException {
	        try {
	        	PrivateKey privateKey = Util.getPrivateKey(privKeyPath);     //NoSuchAlgorithmException InvalidKeySpecException  NullPointerException IOException
	            X509Certificate certificate = Util.getPublicKey(pubKeyPath);
	            Signature signature = new Signature(privateKey, certificate, tsaUrl);   //UnrecoverableKeyException CertificateNotYetValidException CertificateExpiredException //KeyStoreException //NoSuchAlgorithmException //IOException
	            //create temporary pdf file
	            File pdfFile = File.createTempFile("pdf", "");
	            //write bytes to created pdf file
	            FileUtils.writeByteArrayToFile(pdfFile, pdfToSign);
	           
	            //create empty pdf file which will be signed
	            File signedPdf = File.createTempFile("signedPdf", "");
	         
	            //sign pdfFile and write bytes to signedPdf
	            this.signDetached(signature, pdfFile, signedPdf); // (서명, 서명할 파일, 서열된파일) 

	            byte[] signedPdfBytes = Files.readAllBytes(signedPdf.toPath());

	            //remove temporary files
	            pdfFile.deleteOnExit();
	            signedPdf.deleteOnExit();

	            return signedPdfBytes;
	            
	        } catch (NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | KeyStoreException e) {
	        	LOG.error("Exception position : Cannot obtain proper KeyStore or Certificate, msg:"+e.getMessage());
	            throw e;
	        } catch (IOException e) {
	        	LOG.error("Cannot obtain proper file", e);
	        	throw e; 
	        }

	    }


	    private void signDetached(SignatureInterface signature, File inFile, File outFile) throws FileNotFoundException, IOException  {
	        if (inFile == null || !inFile.exists()) {
	        	LOG.error("Exception position : SigningService(FileNotFoundException) - signDetached(SignatureInterface signature, File inFile, File outFile)");
	            throw new FileNotFoundException("Document for signing does not exist");
	        }

	        try (FileOutputStream fos = new FileOutputStream(outFile);
	             PDDocument doc = PDDocument.load(inFile)) {
	             signDetached(signature, doc, fos);
	        } catch (FileNotFoundException e) {
	        	LOG.error("Exception position : signDetached(SignatureInterface signature, File inFile, File outFile), msg:"+e.getMessage());
	        	throw e;
	        } catch (IOException e) {
	        	LOG.error("Exception position : signDetached(SignatureInterface signature, File inFile, File outFile), msg:"+e.getMessage());
	        	throw e; 
	        }
	    }

	    private void signDetached(SignatureInterface signature, PDDocument document, OutputStream output) throws IOException {
	    	 // create signature dictionary
	    	PDSignature pdSignature = new PDSignature();
	    	pdSignature.setType(COSName.DOC_TIME_STAMP);
	        pdSignature.setSubFilter(COSName.getPDFName("ETSI.RFC3161"));
	        pdSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
	        pdSignature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
	        pdSignature.setName("nonghyup");
	        pdSignature.setReason("This file is validated by nonghyeob");

	        // the signing date, needed for valid signature
	        pdSignature.setSignDate(Calendar.getInstance());
	        try {
		        // register signature dictionary and sign interface
		        document.addSignature(pdSignature, signature);

		        // write incremental (only for signing purpose)
		        // use saveIncremental to add signature, using plain save method may break up a document
		        document.saveIncremental(output);
	        } catch (IOException e) {
	        	LOG.error("signDetached(SignatureInterface signature, PDDocument document, OutputStream output), msg:"+e.getMessage());
	        	throw e; 
	        } finally {
	    		if(document != null) try { document.close();} catch(IOException e) { 
	    			LOG.error("document.close(), msg:"+e.getMessage()); 
		    		throw e;
		    	}
	    		if(output != null) try { output.close();} catch(IOException e) { 
	    			LOG.error("output.close(), msg:"+e.getMessage()); 
		    		throw e;
		    	}
	        }

	    }

		@SuppressWarnings({ "static-access", "unchecked" })
		public boolean toBlcokChain(byte[] fileContent, byte[] signedPdf, String makeFileFullPath) throws OperatorCreationException, CMSException, CertificateException, IOException, NoSuchAlgorithmException, ConException, TSPException, NoTimeStampException, DAppException, NoSignerException {
		 	PDDocument doc = null;
	    	TimeStampToken timeStampToken = null;
			try {

		    	//4.각파일을 해쉬함.(블록체인에 저장할 데이터)  
		    	String PDFHashed = Util.getHashFromByteArray(fileContent);    //NoSuchAlgorithmException 
		    	String signedPDFHshed = Util.getHashFromByteArray(signedPdf); //NoSuchAlgorithmException 
		    
		    	//5.토큰이 삽입된 PDF 에서 토큰 추출    	
	    		for(PDSignature sig : doc.load(signedPdf).getSignatureDictionaries()) {
	    		   COSDictionary sigDict = sig.getCOSObject();
	               COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);
	          
	               byte[] byteArray =   sig.getSignedContent(signedPdf);  //IOException
	               CMSProcessable signedContent = new CMSProcessableByteArray(byteArray);
	              
	               byte[] certData = contents.getBytes();
	               CertificateFactory factory = CertificateFactory.getInstance("X.509");  //CertificateException
	               ByteArrayInputStream certStream = new ByteArrayInputStream(certData);
	  		       CMSSignedData signedData = new CMSSignedData(signedContent, contents.getBytes());  //CMSException
	  		       Collection<? extends Certificate> certs = factory.generateCertificates(certStream);
	           
	  		       X509Certificate cert = null;
		           for( Certificate tempCert : certs) {
		        	   if(SigUtils.checkTimeStampCertificateUsage((X509Certificate)tempCert) == false) {
		        		   LOG.error("Exception position: SigUtils.checkTimeStampCertificateUsage");
		        		   throw new NoTimeStampException("Certificate extended key usage does not include timeStamping");
		        	   }
		        	   cert = (X509Certificate) tempCert;
		           }
		  		   Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
			        if (signers.isEmpty())
			        {
			        	LOG.error("Exception position : signers.isEmpty()");
						File file = new File(makeFileFullPath); 
						file.delete();
			            throw new NoSignerException("No signers in signature");
			        }
			        SignerInformation signerInformation = signers.iterator().next();
			        timeStampToken = SigUtils.extractTimeStampTokenFromSignerInformation(signerInformation); //토큰추출. //TSPException
			        
			        //타임스탬프토큰의 유효성 체크
			        if(timeStampToken != null)  SigUtils.validateTimestampToken(timeStampToken, cert);  //OperatorCreationException | TSPException
	    		} //for end 
	    		//타임스탬프토큰 base64인코딩 
	    		String tokenEncodedString = Util.encodeBase64String(timeStampToken.getEncoded());
	    		JSONObject param = new JSONObject();
	    		param.put("pdfHash", PDFHashed);
	    		param.put("pdfTokenHash", signedPDFHshed);
	    		param.put("tst", tokenEncodedString);
	    		
	    		connection.getHttpClient();
	    		HttpResponse httpRes = connection.doPost(tsaUrl + "/" + "insertblc", param);
	    		String resBody = new BasicResponseHandler().handleResponse(httpRes);
	    		Gson gson = new Gson(); 
	         	CommonResult result = gson.fromJson(resBody, CommonResult.class); 
	        	if(result.getCode() != 0) {
	         		LOG.error("TSA_RESPONSE : " + resBody.toString());
		    		File file = new File(makeFileFullPath); 
		    		file.delete(); 
	         		throw new DAppException("DApp Server error");
	         	}
	         	return true;
	    		
			} catch (OperatorCreationException e) {
				LOG.error("Exception position : SigUtils.validateTimestampToken(timeStampToken, cert), msg:"+e.getMessage());
				File file = new File(makeFileFullPath); 
				file.delete();
				throw e;
			} catch (CMSException e) {
				LOG.error("Exception position : new CMSSignedData(signedContent, contents.getBytes()), msg:"+e.getMessage());
				File file = new File(makeFileFullPath); 
				file.delete();
				throw e;
			} catch (CertificateException e) {
				LOG.error("Exception position : CertificateFactory.getInstance(X.509), msg:"+e.getMessage());
				File file = new File(makeFileFullPath); 
				file.delete();
				throw e;
			} catch (IOException e) {
				LOG.error("Exception position : sig.getSignedContent(signedPdf), msg:"+e.getMessage());
				File file = new File(makeFileFullPath); 
				file.delete();
				throw e;
			} catch (NoSuchAlgorithmException e) {
				LOG.error("Exception position : Util.getHashFromByteArray(fileContent), msg:"+e.getMessage());
				File file = new File(makeFileFullPath); 
				file.delete();
				throw e;
			} catch (TSPException e) {
				LOG.error("Exception position : SigUtils.extractTimeStampTokenFromSignerInformation(signerInformation)"
						+ "| SigUtils.validateTimestampToken(timeStampToken, cert), msg:"+e.getMessage());
				File file = new File(makeFileFullPath); 
				file.delete();
				throw e;
			} finally { 
		    	if(doc != null) try { doc.close();} catch(IOException e) { 
		    		LOG.error("doc.close(), msg:"+e.getMessage()); 
		    		throw e;
		    	}
			}
		}
	    

}
