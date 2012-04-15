package com.fscrypto.cipher;

import static org.junit.Assert.*;
import static com.fscrypto.cipher.CipherEngines.*;
import static com.fscrypto.cipher.CipherPaddings.*;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Random;

import javax.security.auth.x500.X500Principal;

import org.junit.Ignore;
import org.junit.Test;

import com.fscrypto.testutils.Utils;

public class PublicKeyCipherTests {
	private static final String[] DEFAULT_ENGINES = {RSA};
	private static final int KEY_SIZES[][] = {{2048, 4096, 256}};
	private static final String KEY_STORE_ENGINES[] = {"JKS", "PKCS12"};
		
	@Test
	public void testEncrypt() throws Exception {
		for (int i = 0; i < DEFAULT_ENGINES.length; ++i) {
			String engine = DEFAULT_ENGINES[i];
			for (int keySize = KEY_SIZES[i][0]; keySize <= KEY_SIZES[i][1]; keySize += KEY_SIZES[i][2]) {
				KeyPairGenerator generator = KeyPairGenerator.getInstance(engine);
				generator.initialize(keySize);
				KeyPair keyPair = generator.generateKeyPair();
				for (String mode : Utils.getSupportedModes(engine)) {
					for (String padding : Utils.getSupportedPaddings(engine)) {
						System.err.println("testEncrypt() with Transform: " + engine + "/" + mode + "/" + padding + 
								   " Key size: " + keySize);			
						for (String keyStoreEngine : KEY_STORE_ENGINES) {
							System.err.println("\tand keystore type: " + keyStoreEngine);
							
							KeyStore keyStore = createKeystore(keyPair, "test", "test", keyStoreEngine, "SHA1withRSA");
							
							byte[] dummyData = new byte[new Random().nextInt(126)];
							new Random().nextBytes(dummyData);
							ByteArrayOutputStream out = new ByteArrayOutputStream();
							
							PublicKeyCipher.encrypt(engine, 
													padding, 
													mode, 
													"JCE", 
													new ByteArrayInputStream(dummyData),
													keyStore, 
													"test", 
													out);
							
							byte[] testOutput = out.toByteArray();
							assertTrue(testOutput.length > 0);
						}
					}
				}
			}
		}
	}

	@Test
	@Ignore
	public void testDecrypt() {
		fail("Not yet implemented");
	}
	
	@Test
	public void testSanity() throws Exception {
		for (int i = 0; i < DEFAULT_ENGINES.length; ++i) {
			String engine = DEFAULT_ENGINES[i];
			for (int keySize = KEY_SIZES[i][0]; keySize <= KEY_SIZES[i][1]; keySize += KEY_SIZES[i][2]) {
				KeyPairGenerator generator = KeyPairGenerator.getInstance(engine);
				generator.initialize(keySize);
				KeyPair keyPair = generator.generateKeyPair();
				for (String mode : Utils.getSupportedModes(engine)) {
					for (String padding : Utils.getSupportedPaddings(engine)) {
						System.err.println("testSanity() with Transform: " + engine + "/" + mode + "/" + padding + 
								   " Key size: " + keySize);			
						for (String keyStoreEngine : KEY_STORE_ENGINES) {
							System.err.println("\tand keystore type: " + keyStoreEngine);
							
							KeyStore keyStore = createKeystore(keyPair, "test", "test", keyStoreEngine, "SHA1withRSA");
							
							byte[] dummyData = new byte[new Random().nextInt(126)];
							new Random().nextBytes(dummyData);
							
							PipedInputStream decryptIn = new PipedInputStream();
							PipedOutputStream encryptOut = new PipedOutputStream(decryptIn);
							PipedInputStream stringInput = new PipedInputStream();
							PipedOutputStream decryptOut = new PipedOutputStream(stringInput);
							
							PublicKeyCipher.encrypt(engine, 
													padding, 
													mode, 
													"JCE", 
													new ByteArrayInputStream(dummyData),
													keyStore, 
													"test", 
													encryptOut);							
							encryptOut.close();							
							PublicKeyCipher.decrypt(engine, 
													padding, 
													mode, 
													"JCE", 
													decryptIn, 
													keyStore, 
													"test", 
													"test", 
													decryptOut);
							decryptOut.close();
							if (NO_PADDING.equalsIgnoreCase(padding)) {
								int startingZeros = 0;
								ByteBuffer buffer = ByteBuffer.allocate(dummyData.length);
								while (dummyData[startingZeros] == 0) {
									++startingZeros;
									buffer.put((byte)0);
								}
								int b = 0;
								while (b == 0) {
									b = stringInput.read();
								}
								buffer.put((byte)b);
								for (int c = stringInput.read(); c != -1; c= stringInput.read()) {
										buffer.put((byte)c);
								}
								byte[] fuckYou = buffer.array();
								assertArrayEquals(dummyData, fuckYou);
							} else {
								assertArrayEquals(dummyData, IOUtils.toByteArray(stringInput));
							}
						}
					}
				}
			}
		}
	}
	
	private KeyStore createKeystore(KeyPair keyPair, 
									String privatePassword, 
									String alias, 
									String engine, 
									String sigAlgorithm) throws Exception {
		KeyStore keyStore = KeyStore.getInstance(engine);
		keyStore.load(null);
		
		X500Principal principal = new X500Principal("CN=Test");
		BigInteger serialNumber = new BigInteger(128, new Random());
		Date begin = new Date(System.currentTimeMillis() - 1000 * 60 * 60 *24);
		Date end = new Date(System.currentTimeMillis() + 1000 * 60 * 60 *24);
		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(principal, 
																			  serialNumber, 
																			  begin, 
																			  end, 
																			  principal, 
																			  keyPair.getPublic());
		
		X509CertificateHolder holder = builder.build(new JcaContentSignerBuilder(sigAlgorithm).build(keyPair.getPrivate()));
		Certificate temp = new JcaX509CertificateConverter().getCertificate(holder);
		Certificate certArray[] = {temp};
		if ("jks".equalsIgnoreCase(engine)) {
			TrustedCertificateEntry cert = new TrustedCertificateEntry(temp);
			keyStore.setEntry(alias, cert, null);
		}
		keyStore.setKeyEntry(alias, keyPair.getPrivate(), privatePassword.toCharArray(), certArray);
		return keyStore;
	}

}
