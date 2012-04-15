package com.fscrypto.cipher;

public class CipherPaddings {
	//Guaranteed provided by JCE===============================================
	public static final String NO_PADDING = "NoPadding";
	public static final String ISO10126 = "ISO10123Padding";
	public static final String PKCS5 = "PKCS5Padding";
	public static final String SSL3 = "SSL3Padding";
	
	//Provided by Bouncycastle=================================================
	public static final String PKCS7 = "PKCS7Padding";
	public static final String CTS_Padding = "WithCTS";
	public static final String TBC = "TBCPadding";
	public static final String ZEROS = "ZeroBytePadding";
	public static final String X923 = "X923Padding";
	public static final String ISO7816 = "ISO7816Padding";
	
	public static String OAEP(String digest, String mgf) {
		return "OAEPWith" + digest + "And" + mgf + "Padding";
	}
}
