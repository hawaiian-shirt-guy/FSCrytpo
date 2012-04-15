package com.fscrypto.cipher;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;

import javax.crypto.Cipher;

import org.apache.commons.io.IOUtils;

public class PublicKeyCipher {
	public static void encrypt(String 		engine, 
							   String 		padding, 
							   String 		mode, 
							   String 		provider, 
							   InputStream 	in, 
							   KeyStore		keyStore,
							   String		keyName,
							   OutputStream	out) throws Exception {
		Key key = keyStore.getCertificate(keyName).getPublicKey();
		Cipher cipher = Cipher.getInstance(engine + "/" + mode + "/" + padding);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] data = IOUtils.toByteArray(in);
		byte[] output = cipher.doFinal(data);
		out.write(output);
	}
				
	public static void decrypt(String 		engine, 
							   String 		padding, 
							   String 		mode, 
							   String 		provider, 
							   InputStream 	in, 
							   KeyStore		keyStore,
							   String		keyName,
							   String		keyPassword,
							   OutputStream	out) throws Exception {
		Key key = keyStore.getKey(keyName, keyPassword.toCharArray());
		Cipher cipher = Cipher.getInstance(engine + "/" + mode + "/" + padding);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] data = IOUtils.toByteArray(in);
		byte[] output = cipher.doFinal(data);
		out.write(output);
	}
}
