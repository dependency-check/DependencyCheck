package org.owasp.dependencycheck.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.util.Base64;
import java.util.UUID;

import org.apache.hc.client5.http.auth.BearerToken;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.junit.Test;

public class CredentialHelperTest {

	// make sure that getting a string from settings for a non defined property key doesn't throw an exception and returns the default value
	@Test
	public void test_settings_null() throws Exception {
		Settings settings = new Settings();
		String expected = UUID.randomUUID().toString();
		assertNotNull(settings.getString(Downloader.NO_PROPERTY_DEFINED, expected));
		assertEquals(expected, settings.getString(Downloader.NO_PROPERTY_DEFINED, expected));
	}	

	@Test
	public void testBaseFunctions() throws Exception {
		String user = UUID.randomUUID().toString();
		String password = UUID.randomUUID().toString();
		String b64 = StandardAuthScheme.BASIC + " " + Base64.getEncoder().encodeToString((user+":"+password).getBytes());
		int start = StandardAuthScheme.BASIC.length() + 1;

		// starts with
		assertTrue(CredentialHelper.startsWith(b64.toCharArray(), StandardAuthScheme.BASIC));
		assertFalse(CredentialHelper.startsWith(b64.toCharArray(), StandardAuthScheme.BEARER));

		// Basic auth
		assertEquals(user, CredentialHelper.getBasicUser(b64.toCharArray(), start));
		assertEquals(password, new String(CredentialHelper.getBasicPassword(b64.toCharArray(), start)));
	}
	
	

	///////////////////////////////////////////////////
	// test basic auth methods
	///////////////////////////////////////////////////
	
	@Test
	public void testGetBasicCredentials() throws Exception {
		String user = "U-" + UUID.randomUUID().toString();
		String pass = "P-" + UUID.randomUUID().toString();
		String auth = StandardAuthScheme.BASIC + " " + Base64.getEncoder().encodeToString(((user + ":" + pass).getBytes()));

		
		Credentials credentials = CredentialHelper.getBasicCredentialsFromAuthHeader(auth.toCharArray());
		assertNotNull(credentials);
		assertTrue(credentials instanceof UsernamePasswordCredentials);
		assertEquals(user, ((UsernamePasswordCredentials) credentials).getUserName());
		assertEquals(pass, new String(((UsernamePasswordCredentials) credentials).getUserPassword()));
		
		checkBasicException(null);
		checkBasicException("".toCharArray());
		checkBasicException(" ".toCharArray());
		checkBasicException("12323333333333 33".toCharArray());
		auth = StandardAuthScheme.BASIC + " ";
		checkBasicException(auth.toCharArray());
		auth = StandardAuthScheme.BASIC + " !!!!!!!!!!!!!!!!!!!!!!!!";
		checkBasicException(auth.toCharArray());
		auth = StandardAuthScheme.BASIC + " " + Base64.getEncoder().encodeToString(((user + ":" + pass).getBytes()))+"1";
		checkBasicException(auth.toCharArray());		
	}	

	@Test
	public void testCredsBasic() throws Exception {
		String user = "U1-" + UUID.randomUUID().toString();
		String password = "P1-" + UUID.randomUUID().toString();
		
		// no auth
		URL url = new URL("http://127.0.0.1/index.cgi");
		checkBasicCreds(url, user, password, "", "", user, password); 
		url = new URL("https://127.0.0.1/index.cgi");
		checkBasicCreds(url, user, password, "", "", user, password); 

		// user, password and auth
		String user2 = "U2-" + UUID.randomUUID().toString();
		String password2 = "P2-" + UUID.randomUUID().toString();
		String b64 = StandardAuthScheme.BASIC + " " 
				+ Base64.getEncoder().encodeToString((user2+":"+password2).getBytes());
		url = new URL("http://127.0.0.1/index.cgi");
		checkBasicCreds(url, user, password, "", b64, user2, password2); 
		url = new URL("https://127.0.0.1/index.cgi");
		checkBasicCreds(url, user, password, "", b64, user2, password2); 

		// only auth
		url = new URL("http://127.0.0.1/index.cgi");
		checkBasicCreds(url, null, null, "", b64, user2, password2); 
		url = new URL("https://127.0.0.1/index.cgi");
		checkBasicCreds(url, null, null, "", b64, user2, password2); 
	}
	
	@Test
	public void testCredsBasicException() throws Exception {
		// no password
		URL url = new URL("https://127.0.0.1/index.cgi");
		String pfx = "U-";
		checkException(url, pfx+UUID.randomUUID().toString(), null, null, "no password", pfx);
		checkException(url, null, null, UUID.randomUUID().toString(),
				"supported", StandardAuthScheme.BASIC, StandardAuthScheme.BEARER);
	}


	///////////////////////////////////////////////////
	// test bearer auth methods
	///////////////////////////////////////////////////

	@Test
	public void testGetBearerCredentials() throws Exception {
		String token = "token-" + UUID.randomUUID();
		String auth = StandardAuthScheme.BEARER + " " + token;

		Credentials credentials = CredentialHelper.getBearerCredentialsFromAuthHeader(auth.toCharArray());
		assertNotNull(credentials);
		assertTrue(credentials instanceof BearerToken);
		assertEquals(token, ((BearerToken) credentials).getToken());

		checkBearerException(null);
		checkBearerException(new char[0]);
		auth = UUID.randomUUID().toString();
		checkBearerException(auth.toCharArray());
		auth = StandardAuthScheme.BEARER + UUID.randomUUID().toString();
		checkBearerException(auth.toCharArray());		
		auth = StandardAuthScheme.BEARER + " ";
		checkBearerException(auth.toCharArray());		
	}
	
	@Test
	public void testCredsTokenAuth() throws Exception {
		String user = "U1-" + UUID.randomUUID().toString();
		String password = "P1-" + UUID.randomUUID().toString();
		String token = "token-" + UUID.randomUUID();
		String auth = StandardAuthScheme.BEARER + " " + token;
		
		// with user / password
		URL url = new URL("http://127.0.0.1/index.cgi");
		checkTokenCreds(url, user, password, "", auth, token); 
		url = new URL("https://127.0.0.1/index.cgi");
		checkTokenCreds(url, user, password, "", auth, token); 
		
		// without user / password
		url = new URL("http://127.0.0.1/index.cgi");
		checkTokenCreds(url, null, null, "", auth, token); 
		url = new URL("https://127.0.0.1/index.cgi");
		checkTokenCreds(url, null, null, "", auth, token); 
	}

	
	@Test
	public void testCredsToken() throws Exception {
		String token = "token-" + UUID.randomUUID();
		URL url;
		
		// without user / password
		url = new URL("http://127.0.0.1/index.cgi");
		checkTokenCreds(url, null, null, token, "",	token); 
		url = new URL("https://127.0.0.1/index.cgi");
		checkTokenCreds(url, null, null, token, "", token); 
	}

	@Test
	public void testCredsTokenException() throws Exception {
		String auth = StandardAuthScheme.BEARER + " ";
		URL url = new URL("https://127.0.0.1/index.cgi");
		checkException(url, null, null, null, auth, "empty bearer token");		
		checkException(url, null, null, null, StandardAuthScheme.BEARER, "should start with");		
	}

	
	

	///////////////////////////////////////////////////
	// private test methods
	///////////////////////////////////////////////////

	private void checkException(URL url, String user, String password, String token,
			String auth, String ... messages) throws Exception {
        if(password == null) password = "";
        if(auth == null) auth = "";
        if(token == null) token = "";
        try {
            CredentialHelper.getCredentials(url.toString(), 
            		user, password.toCharArray(),
            		token.toCharArray(), auth.toCharArray());
            throw new Exception("should have thrown an InvalidSettingException");
        } catch(InvalidSettingException ok) {
			assertNotNull(ok);
			if(messages==null || messages.length == 0)
				return;
			assertNotNull(ok.getMessage());
			for(String message : messages) {
				assertTrue(ok.getMessage().toLowerCase().contains(message.toLowerCase()));
			}
        }		
	}




	private void checkTokenCreds(URL url, String user, String password, String token, String auth, 
			String expectedToken) throws Exception {
        if(password == null) password = "";
        if(auth == null) auth = "";
        if(token == null) token = "";
        Credentials creds = CredentialHelper.getCredentials(url.toString(), 
        		user, password.toCharArray(),
        		token.toCharArray(), auth.toCharArray());

		assertTrue(creds instanceof BearerToken);
		BearerToken bearer = (BearerToken) creds;
		assertEquals(expectedToken, bearer.getToken());
	}

	
	private void checkBasicCreds(URL url, String user, String password, 
			String token, String auth, 
			String expectedUser, String expectedPassword) throws Exception {
        if(password == null) password = "";
        if(token == null) token = "";
        Credentials creds = CredentialHelper.getCredentials(url.toString(), 
        		 user, password.toCharArray(),
        		token.toCharArray(), auth.toCharArray());
        
		assertTrue(creds instanceof UsernamePasswordCredentials);
		UsernamePasswordCredentials basicCreds = (UsernamePasswordCredentials) creds;
		assertEquals(expectedUser, basicCreds.getUserName());
		assertEquals(expectedPassword, new String(basicCreds.getUserPassword()));
	}

	private void checkBasicException(char[] auth) throws Exception {
	      try {
	        CredentialHelper.getBasicCredentialsFromAuthHeader(auth);
	        throw new Exception("should have thrown an InvalidSettingException");
	    } catch(InvalidSettingException ok) {
	    	assertNotNull(ok);
			assertNotNull(ok.getMessage());
	   }
	}

	private void checkBearerException(char[] auth) throws Exception {
       try {
            CredentialHelper.getBearerCredentialsFromAuthHeader(auth);
            throw new Exception("should have thrown an InvalidSettingException");
        } catch(InvalidSettingException ok) {
			assertNotNull(ok);
			assertNotNull(ok.getMessage());
        }
	}

}
