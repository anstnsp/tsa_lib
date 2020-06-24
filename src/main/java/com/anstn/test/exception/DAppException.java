package com.anstn.test.exception;


public class DAppException extends Exception {
	private static final long serialVersionUID = 3890060100482339953L;

	private int code;
	private String msg; 
	
	public DAppException(String msg, Throwable t) {
		super(msg, t); 
	}
	
	public DAppException(String msg) {
		this.msg = msg;
	}
	
	public DAppException() {
		super(); 
	}

	public int getCode() {
		return code;
	}

	public String getMsg() {
		return msg;
	}
	
}
