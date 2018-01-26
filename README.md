# SSLogin_Django
## 介绍
  登录注册模块，验证通过邮箱，可以发送验证链接。安全方面采用RSA+AES加密。
## 使用方法
  本项目代码为django服务器端代码，可以提供登录注册的api客户端提供java示例代码：

```Java
package bb;
import java.awt.List;
import java.awt.RenderingHints.Key;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.cookie.Cookie;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONObject;
public class Netapi {
	private String basePath="http://127.0.0.1:8000/bapi/";
	private String loginPath_COMPUTER=basePath+"login/";
	private String registerPath=basePath+"register/";
	public final static int PLATFORM_COMPUTER=0;
	public final static int PLATFORM_PHONE=1;
	private final  String AESkey="fj*&29Jji8@@pP0$";
	private final  String RSApubkey="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrSEEP7qONtFruk6ADahGFTVg8" + 
			"wZdZo+i3PgNdq73uZ5KXHub3XhETKO5wtkojLYdPu9uWanmQ8Uy0yrkWDIvtjzbe" + 
			"XLaaNHMEsMG9pKbbKKCN13reMyge+fQHxubLQZumenL08s1xjqpA61QitZ6KEah+" + 
			"DmVFkjQIPrON65yQuQIDAQAB";
	
	private CookieStore httpCookieStore = new BasicCookieStore();
	
	/**
	 * 用户注册接口（用户注册以后需要验证邮箱） 
	 * @param username
	 * @param password
	 * @param mail email地址
	 * @return 
	 */
	public boolean register(String username,String password,String email) {
		String content="{\"username\":\""+username+"\",\"password\":\""+this.MD5encrypt(password)+"\"}";
		JSONObject j=new JSONObject(content);
		j.put("email", email);
		content=j.toString();
		String result;
		try {
			result=this.securityPost(registerPath, content);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		System.out.println(result);
		return false;
		
		
	}
	/**
	 * 用户进行登录的接口
	 * @param username 用户名
	 * @param password 密码
	 * @param platform 用户使用的平台 取值为 
	 * @return
	 * TODO:二次的aes加密的初始密码需要随机产生，目前使用AESkey
	 */
	public boolean login(String username,String password,int platform ) {
		String content="{\"username\":\""+username+"\",\"password\":\""+this.MD5encrypt(password)+"\"}";
		String result;
		try {
			result=this.securityPost(loginPath_COMPUTER, content);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		System.out.println(result);
		return false;
		
	}

/**
 * 如果需要验证码登录
 * @param username
 * @param password
 * @param platform
 * @param verificationCode
 * @return
 */
	public boolean login(String username,String password,int platform,String verificationCode ) {
		return false;
		
	}
	/** 
	 * 随机生成AES秘钥 
	 */  
	private byte[] getRandomAESkey(){    
	    try {    
	        KeyGenerator kg = KeyGenerator.getInstance("AES");    
	        kg.init(128);//要生成多少位，只需要修改这里即可128, 192或256    
	        SecretKey sk = kg.generateKey();    
	        byte[] b = sk.getEncoded();    
	  return b;
	    } catch (NoSuchAlgorithmException e) {    
	        e.printStackTrace();    
	        System.out.println("生成随机AESkey出错。"); 
	        
	    }   
	    return null;
	}    

	/** 
	 * AES加密 
	 *  
	 * @param content 需要加密的内容 
	 * @param seckey  加密密码 
	 * @return 加密结果

	 * @throws Exception 

	 */  
	private byte[] AESencrypt(byte[] content, String seckey) throws  Exception {  
		
	    // 判断Key是否正确  
	        if (seckey == null) {  
	            System.out.print("Key为空null");  
	            return null;  
	        }  
	        // 判断Key是否为16位  
	        if (seckey.length() != 16) {  
	            System.out.print("Key长度不是16位");  
	            return null;  
	        }  
	        byte[] raw = seckey.getBytes("ASCII");  
	       // while cbc_mode IvParameterSpec iv=new IvParameterSpec("0000000000000000".getBytes());
	        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");  
	        //
	        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  
	        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);  
	        byte[] encrypted = cipher.doFinal(content);  
	        return encrypted;  
	}   
	/** 
	 * AES加密 
	 *  
	 * @param content 需要加密的内容 
	 * @param seckey  加密密码 
	 * @return 加密结果

	 * @throws Exception 

	 */  
	private byte[] AESencrypt(byte[] content, byte[] seckey) throws  Exception {  
		
	        byte[] raw = seckey; 
	       // while cbc_mode IvParameterSpec iv=new IvParameterSpec("0000000000000000".getBytes());
	        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");  
	        //
	        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  
	        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);  
	        byte[] encrypted = cipher.doFinal(content);  
	        return encrypted;  
	} 

	/**
	 * RSA加密
	 * @param content
	 * @param seckey
	 * @return
	 * @throws Exception
	 */
    private  byte[] RSAencrypt(byte[] data, String key)  
            throws Exception {  
        // 对公钥解密  
    	Base64.Decoder decoder=Base64.getDecoder();
    	
        byte[] keyBytes = decoder.decode(key);

   
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);  
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
        PublicKey publicKey =  keyFactory.generatePublic(spec);  
  
        // 对数据加密  
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());  
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
  
        return cipher.doFinal(data);  
    }  
    /**利用MD5进行加密
     * @param str  待加密的字符串
     * @return  加密后的字符串
     * @throws NoSuchAlgorithmException  没有这种产生消息摘要的算法
     * @throws UnsupportedEncodingException  
     */
    private String MD5encrypt(String str) {
        //确定计算方法
        MessageDigest md5 = null;
		try {
			md5 = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        Encoder encoder=Base64.getEncoder();
        
        //加密后的字符串
        String newstr = null;
		try {
			newstr = encoder.encodeToString(md5.digest(str.getBytes("utf-8")));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return newstr;
    }
    /**
     * 加密的post post上去的数据格式为
     * {
     * “params”：data加密后的结果
     * “enseckey”：随机key的加密结果
     * }
     * @param url 路径
     * @param data 数据
     * @return
     * @throws Exception 
     */
    private String securityPost(String url, String data) throws Exception {
    	byte [] b1=this.AESencrypt(data.getBytes(), AESkey);
		 byte[] random_AESkey=getRandomAESkey();
		byte [] b2=this.AESencrypt(b1,random_AESkey);
		String b64_params = Base64.getEncoder().encodeToString(b2);  
		
		byte[] b3=this.RSAencrypt(random_AESkey, this.RSApubkey);
		String b64_encSecKey = Base64.getEncoder().encodeToString(b3);  
		JSONObject jsonParams=new JSONObject();
		jsonParams.put("params", b64_params);
		jsonParams.put("encSecKey", b64_encSecKey);
		//String postS="params="+b64_params+"&encSecKey="+b64_encSecKey;
		//System.out.println(postS);
		return this.httpPostWithJSON(url, jsonParams);
    }

	    /**
	     * 向指定URL发送GET方法的请求
	     * 
	     * @param url
	     *            发送请求的URL
	     * @param param
	     *            请求参数，请求参数应该是 name1=value1&name2=value2 的形式。
	     * @return URL 所代表远程资源的响应结果
	     */
	   private String sendGet(String url, String param) {
	        String result = "";
	        BufferedReader in = null;
	        try {
	            String urlNameString = url + "?" + param;
	            URL realUrl = new URL(urlNameString);
	            // 打开和URL之间的连接
	            URLConnection connection = realUrl.openConnection();
	            // 设置通用的请求属性
	            connection.setRequestProperty("accept", "*/*");
	            connection.setRequestProperty("connection", "Keep-Alive");
	            connection.setRequestProperty("user-agent",
	                    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");
	            // 建立实际的连接
	            connection.connect();

	            // 定义 BufferedReader输入流来读取URL的响应
	            in = new BufferedReader(new InputStreamReader(
	                    connection.getInputStream()));
	            String line;
	            while ((line = in.readLine()) != null) {
	                result += line;
	            }
	        } catch (Exception e) {
	            System.out.println("发送GET请求出现异常！" + e);
	            e.printStackTrace();
	        }
	        // 使用finally块来关闭输入流
	        finally {
	            try {
	                if (in != null) {
	                    in.close();
	                }
	            } catch (Exception e2) {
	                e2.printStackTrace();
	            }
	        }
	        return result;
	    }
	   private String sessionId;
	   private String getSessionId() {
		   return sessionId;
	   }
	   private boolean setSessionId(String sessionId) {
		   this.sessionId=sessionId;
		   return true;
	   }
	   /**
	    * 发送json 数据
	    * @param url
	    * @param jsonParam
	    * @return
	    * @throws Exception
	    */
		private String httpPostWithJSON(String url,JSONObject jsonParam) throws Exception {
			/* init client */
			HttpClient client = null;
			//BasicClientCookie cookie = new BasicClientCookie("sessionid", getSessionId());
			//httpCookieStore.addCookie(arg0);
			HttpClientBuilder builder = HttpClientBuilder.create().setDefaultCookieStore(this.httpCookieStore);
			client = builder.build();
			
			
	        HttpPost httpPost = new HttpPost(url);
	       // CloseableHttpClient client = HttpClients.createDefault();
	       // client.getParams().setCookiePolicy(CookiePolicy.BROWSER_COMPATIBILITY); 
	        String respContent = null;
	      //  HttpClient httpClient = new DefaultHttpClient();
//	        json方式
	        StringEntity entity = new StringEntity(jsonParam.toString(),"utf-8");//解决中文乱码问题    
	        entity.setContentEncoding("UTF-8");    
	        entity.setContentType("application/json");    
	        httpPost.setEntity(entity);
	        System.out.println();
	        
	    
//	        表单方式
//	        List<BasicNameValuePair> pairList = new ArrayList<BasicNameValuePair>(); 
//	        pairList.add(new BasicNameValuePair("name", "admin"));
//	        pairList.add(new BasicNameValuePair("pass", "123456"));
//	        httpPost.setEntity(new UrlEncodedFormEntity(pairList, "utf-8"));   
	        
	        
	        HttpResponse resp = client.execute(httpPost);
	        if(resp.getStatusLine().getStatusCode() == 200) {
	            HttpEntity he = resp.getEntity();
	            respContent = EntityUtils.toString(he,"UTF-8");
	        }

	        /* check cookies */
	        System.out.println(httpCookieStore.getCookies().get(0).getValue());
	        
	        return respContent;
	    }
}
```
```Java
 public static void main(String[] args) {
	  Netapi api=new Netapi();
	  try {
		api.login("username", "password", api.PLATFORM_COMPUTER);
	} catch (Exception e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	  try {
		api.login("username", "password", api.PLATFORM_COMPUTER);
	} catch (Exception e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	//  api.register("test", "123456", "wolianlxw@sina.com");
  }
```
