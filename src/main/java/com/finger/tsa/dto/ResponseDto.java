package com.finger.tsa.dto;

public class ResponseDto {
	private String pdfHash; 		//원본pdf해쉬 
	private String pdfTokenHash; 	//토큰이삽입된 pdf해쉬
	private String tst; 			//타임스탬프 토큰 
	private String issuerDate; 		//토큰만들때 시점
	private String docuSeq; 		//문서일련번호
	
	public ResponseDto() {}

	public String getPdfHash() {
		return pdfHash;
	}

	public void setPdfHash(String pdfHash) {
		this.pdfHash = pdfHash;
	}

	public String getPdfTokenHash() {
		return pdfTokenHash;
	}

	public void setPdfTokenHash(String pdfTokenHash) {
		this.pdfTokenHash = pdfTokenHash;
	}

	public String getTst() {
		return tst;
	}

	public void setTst(String tst) {
		this.tst = tst;
	}

	public String getIssuerDate() {
		return issuerDate;
	}

	public void setIssuerDate(String issuerDate) {
		this.issuerDate = issuerDate;
	}

	public String getDocuSeq() {
		return docuSeq;
	}

	public void setDocuSeq(String docuSeq) {
		this.docuSeq = docuSeq;
	}
	
}
