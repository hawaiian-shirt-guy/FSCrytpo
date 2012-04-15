package com.fscrypto.testutils;

import java.security.Provider;

import javax.crypto.Cipher;

public class Utils {
	public static String[] getSupportedModes(String algorithm) throws Exception {
		Cipher cipher = Cipher.getInstance(algorithm);
		Provider provider = cipher.getProvider();
		Provider.Service service = provider.getService("Cipher", algorithm);
		String modes = service.getAttribute("SupportedModes");
		return modes.split("\\|");
	}
	
	public static String[] getSupportedPaddings(String algorithm) throws Exception {
		Cipher cipher = Cipher.getInstance(algorithm);
		Provider provider = cipher.getProvider();
		Provider.Service service = provider.getService("Cipher", algorithm);
		String modes = service.getAttribute("SupportedPaddings");
		return modes.split("\\|");
	}
	
	public static int getBlockSize(String algorithm) throws Exception {
		Cipher cipher = Cipher.getInstance(algorithm);
		return cipher.getBlockSize();
	}
}
