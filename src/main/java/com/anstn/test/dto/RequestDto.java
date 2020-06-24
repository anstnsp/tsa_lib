package com.anstn.test.dto;



public class RequestDto {
	private String tst;
	private String pdfTokenHash; 
	
	public RequestDto() {}
	
	public RequestDto(String tst, String pdfTokenHash) {
		this.tst = tst;
		this.pdfTokenHash = pdfTokenHash;
	}

	public String getTst() {
		return tst;
	}

	public void setTst(String tst) {
		this.tst = tst;
	}

	public String getPdfTokenHash() {
		return pdfTokenHash;
	}

	public void setPdfTokenHash(String pdfTokenHash) {
		this.pdfTokenHash = pdfTokenHash;
	}

	
}
