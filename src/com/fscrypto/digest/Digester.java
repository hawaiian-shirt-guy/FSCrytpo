package com.fscrypto.digest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import com.fscrypto.utils.InputStreamReadCallback;
import com.fscrypto.utils.InputStreamReader;

//TODO: What do we want to do with this throws clause?
/**
 * This class is used to provide cryptographic hashes of data using standard message digest algorithms
 * @author john_larison
 * @since 0.1.ALPHA
 * @see Algorithms
 */
public class Digester {
	
	/**
	 * Workhorse method for the Digester class.  Used to calculate cryptographic hashes 
	 * @param algorithm The hashing algorithm to use
	 * @param in The {@link InputStream} from which to read to data to hash
	 * @param out The {@link OutputStream} to which to write the hash
	 * @throws IOException If an exception occurs with the underlying IO mechanisms
	 * @throws GeneralSecurityException If an exception occurs within the underlying cryptographic framework
	 */
	public static void generateHash(String 			algorithm, 
									InputStream 	in, 
									OutputStream	out) throws IOException, GeneralSecurityException {
		final MessageDigest digester = MessageDigest.getInstance(algorithm);
		InputStreamReader.read(in, new InputStreamReadCallback() {
			@Override
			public void update(byte b) throws GeneralSecurityException {
				digester.update(b);
			}
			
			@Override
			public void update(byte[] bytes) throws GeneralSecurityException {
				digester.update(bytes);				
			}
		});
		out.write(digester.digest());
	}
}
