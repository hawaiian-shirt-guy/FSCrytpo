package com.fscrypto.cipher;

public class CipherModes {
	//Guaranteed provided by JCE===============================================
	public static final String NO_MODE = "NONE";
	public static final String CBC = "CBC";
	public static final String CFB = "CFB";
	public static final String ECB = "ECB";
	public static final String OFB = "OFB";
	public static final String PCBC = "PCBC";
	public static final String CTS_Mode = "CTS";
	public static final String CTR = "CTR";
		
	//Provided by Bouncycastle=================================================
	public static final String SIC = "SIC";
	public static final String OPEN_PGPCFB = "OpenPGPCFB";
	public static final String GOFB = "GOFB";
	public static final String CCM = "CCM";
	public static final String EAX = "EAX";
}
