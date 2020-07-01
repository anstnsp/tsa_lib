package com.finger.tsa.exception;


public class NoTimeStampException extends Exception{

	private static final long serialVersionUID = 3890060100482339953L;

	private int code;
	private String msg; 
	
	public NoTimeStampException(String msg, Throwable t) {
		super(msg, t); 
	}
	
	public NoTimeStampException(String msg) {
		this.msg = msg;
	}
	
	public NoTimeStampException() {
		super(); 
	}

	public int getCode() {
		return code;
	}

	public String getMsg() {
		return msg;
	}
	
	
}
