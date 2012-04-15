package com.fscrypto.cipher;

import static com.fscrypto.cipher.CipherModes.*;

import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;

public class SymmetricCipher {
	public static void encrypt(String 		engine, 
							   String 		padding, 
							   String 		mode, 
							   String 		provider, 
							   InputStream 	in, 
							   InputStream 	key, 
							   OutputStream	out) throws Exception {
		SecretKeySpec keySpec = new SecretKeySpec(IOUtils.toByteArray(key), engine);
		Cipher cipher = Cipher.getInstance(engine + "/" + mode + "/" + padding);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec);
		
		byte[] iv = cipher.getIV();
		if (iv != null) {
			out.write(iv);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
		}
		
		byte[] output = cipher.doFinal(IOUtils.toByteArray(in));
		out.write(output);
	}
	
	public static void decrypt(String 		engine, 
			   				   String 		padding, 
			   				   String 		mode, 
			   				   String 		provider, 
			   				   InputStream 	in, 
			   				   InputStream 	key, 
			   				   OutputStream	out) throws Exception {
		SecretKeySpec keySpec = new SecretKeySpec(IOUtils.toByteArray(key), engine);
		Cipher cipher = Cipher.getInstance(engine + "/" + mode + "/" + padding);
		
		if (!(NO_MODE.equalsIgnoreCase(mode) || ECB.equals(mode))) {
			byte[] iv = new byte[cipher.getBlockSize()];
			in.read(iv);
			cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
		} else {
			cipher.init(Cipher.DECRYPT_MODE, keySpec);
		}
		
		byte[] output = cipher.doFinal(IOUtils.toByteArray(in));
		out.write(output);
	}
}
