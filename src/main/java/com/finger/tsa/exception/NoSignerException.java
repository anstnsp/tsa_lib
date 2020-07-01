package com.finger.tsa.exception;

public class NoSignerException extends Exception {


	private static final long serialVersionUID = -8145351717214881769L;
	private int code;
	private String msg; 
	
	public NoSignerException(String msg, Throwable t) {
		super(msg, t); 
	}
	
	public NoSignerException(String msg) {
		this.msg = msg;
	}
	
	public NoSignerException() {
		super(); 
	}

	public int getCode() {
		return code;
	}

	public String getMsg() {
		return msg;
	}
	
	
}