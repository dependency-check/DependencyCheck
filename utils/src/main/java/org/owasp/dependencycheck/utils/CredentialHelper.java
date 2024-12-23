package org.owasp.dependencycheck.utils;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

import org.apache.hc.client5.http.auth.BearerToken;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;

public class CredentialHelper {
    /**
     * Get credentials from the provided settings
     * @param theUser    Username for a Basic auth
     * @param thePass    Password for a Basic auth
     * @param theToken    Token for a Bearer auth, takes precedence over user/password
     * @param theAuth Authorization header value, e.g. 'Basic dXNlcjpwYXNzd29yZA==', takes precedence over user/password or token
     * 
     * @return credentials
     * @throws InvalidSettingException
     */
    public static Credentials getCredentials(String theUser, char[] thePass, char[] theToken, char[] theAuth) throws InvalidSettingException {
        Credentials _creds = null;
         
        // create a basic auth for user and password, if provided
        if (theUser != null && !theUser.isBlank()) {
            if(thePass == null || thePass.length == 0)
                throw new InvalidSettingException("no password provided for user " + theUser);
               try {
                   _creds = new UsernamePasswordCredentials(theUser, thePass);
               } catch (Exception e) {
                throw new InvalidSettingException("invalid user or password");                               
               }
        }
        
        // create a bearer token, if provided, takes precedence over user/password
        if (theToken != null && theToken.length > 0) {
            _creds = new BearerToken(new String(theToken));
        }
        
        // if an auth has been passed, takes precedence over user/password/token
        if (theAuth != null && theAuth.length > 0) {
            if(startsWith(theAuth,StandardAuthScheme.BASIC)) {
                _creds = getBasicCredentialsFromAuthHeader(theAuth);
            } else if(startsWith(theAuth, StandardAuthScheme.BEARER)) {
                _creds = getBearerCredentialsFromAuthHeader(theAuth);
            } else
                throw new InvalidSettingException("unknown authentication scheme. "
                        + "Supported authentication schemes are " 
                        + StandardAuthScheme.BASIC + " and " + StandardAuthScheme.BEARER);                               
        }
        return _creds;
    }

    /**
     * Create a bearer token credentials from the auth header
     * @param authHeader
     * @return credentials
     * @throws InvalidSettingException
     */
    protected static Credentials getBearerCredentialsFromAuthHeader(char[] authHeader) throws InvalidSettingException {
        if (authHeader == null || authHeader.length == 0)
            throw new InvalidSettingException("empty authentication header");
        try {
            // get token
            String token = new String(authHeader);
            if(!token.startsWith(StandardAuthScheme.BEARER + " "))
                throw new InvalidSettingException("auth header should start with [" + StandardAuthScheme.BEARER + " ]");
            token = token.replaceAll("^" + Pattern.quote(StandardAuthScheme.BEARER),"").trim();
            if(token.isBlank())
                throw new InvalidSettingException("empty bearer token");
            return new BearerToken(token);
        } catch (Exception e) {
            throw new InvalidSettingException(e.getMessage());                               
        }
    }

    /**
     * Create a basic credentials from the basic auth header
     * @param authHeader
     * @return credentials
     * @throws InvalidSettingException
     */
    protected static Credentials getBasicCredentialsFromAuthHeader(char[] authHeader) throws InvalidSettingException {
        if (authHeader == null || authHeader.length == 0)
            throw new InvalidSettingException("empty authentication header");
        try {
            // decode B64 to get user and password
            String user = getBasicUser(authHeader, StandardAuthScheme.BASIC.length() + 1); 
            return new UsernamePasswordCredentials(
                    user,
                    getBasicPassword(authHeader, StandardAuthScheme.BASIC.length() + 1)
                    );
        } catch (Exception e) {
            throw new InvalidSettingException(e.getMessage());                               
        }
    }



    /**
     * copy a char array into an array of bytes without using a String
     * @param in
     * @param start where to start in the array if chars
     * @return byte array
     * @throws InvalidSettingException 
     */
    protected static byte[] toBytes(char[] in, int start) throws InvalidSettingException {
        if (in == null || in.length == 0)
            throw new InvalidSettingException("empty authentication provided");
        if(start >= in.length)
            throw new InvalidSettingException("invalid authentication provided - too short");
        char[] chars = new char[in.length - start];
        for(int i = start; i < in.length; i++) {
            chars[i-start] = in[i];
        }
        CharBuffer charBuffer = CharBuffer.wrap(chars);
        ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
        byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
                byteBuffer.position(), byteBuffer.limit());
        Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
        return bytes;
    }
    
    /**
     * get the user out of a b64 string (Basic auth)
     * @param in
     * @param start
     * @return
     * @throws InvalidSettingException
     */
    protected static String getBasicUser(char[] in, int start) throws InvalidSettingException {
        if (in == null || in.length == 0)
            throw new InvalidSettingException("invalid authentication string for the username");
        if(start >= in.length)
            throw new InvalidSettingException("authentication string too short for the username");
        byte[] src = toBytes(in, start);
        if(src == null || src.length ==0)
            return null;
        byte[] decoded = Base64.getDecoder().decode(src);
        String user = "";
        for(int i = 0; i < decoded.length; i++) {
            if(decoded[i]!=':') user += (char) decoded[i];
            else return user;
        }
        throw new InvalidSettingException("unable to find the username");
    }
    
    /**
     * get the password out of a B64 string  (Basic auth)
     * @param in
     * @param start
     * @return
     * @throws InvalidSettingException
     */
    protected static char[] getBasicPassword(char[] in, int start) throws InvalidSettingException {
        if (in == null || in.length == 0)
            throw new InvalidSettingException("invalid authentication string for the pasword");
        if(start >= in.length)
            throw new InvalidSettingException("authentication string too short for the password");
        byte[] src = toBytes(in, start);
        if(src == null || src.length ==0)
            return null;
        byte[] decoded = Base64.getDecoder().decode(src);
        start = 0;
        for(int i = 0; i < decoded.length && start == 0; i++) {
            if(decoded[i] == ':') start = i + 1;
        }
        if(start == 0 || start >= decoded.length)
            throw new InvalidSettingException("unable to find the password");
        
        char[] password = new char[decoded.length - start];
        for(int i = start; i < decoded.length; i++) {
            password[i - start] = (char) (decoded[i] & 0xFF) ;
        }
        return password;
    }

    /**
     * Utility function to perform startsWith on a char array
     * @param in
     * @param start
     * @return
     */
    protected static boolean startsWith(char[] in, String start) {
        if (in == null || in.length == 0)
            return false;
        if (start == null || start.isBlank())
            return false;
        if(start.length() > in.length)
            return false;
        for(int i = 0; i < start.length(); i++) {
            if(start.charAt(i) != in[i]) return false;
        }
        return true;
    }

}
