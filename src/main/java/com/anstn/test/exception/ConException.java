package com.anstn.test.exception;





public class ConException extends Exception{

	private static final long serialVersionUID = -4672061172588337965L;
	private int code;
	private String msg; 
	
	public ConException(String msg, Throwable t) {
		super(msg, t); 
	}
	
	public ConException(String msg) {
		this.msg = msg;
	}
	
	public ConException() {
		super(); 
	}

	public int getCode() {
		return code;
	}

	public String getMsg() {
		return msg;
	}


	
	
}
