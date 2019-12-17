package xyz.xy718.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;


/**
 * JWT生成-校验工具
 *<br>
 * 今天熬夜了，难受
 * @author Xy718
 */
@Component
public class JwtHelper {

    //token 过期时间, 单位: 毫秒   7200000表示两小时
    private static long TOKEN_EXPIRED_TIME = 7200000;
    @Value("${jwt.exp_time}")
    public void setTOKEN_EXPIRED_TIME(Long tOKEN_EXPIRED_TIME) {
    	TOKEN_EXPIRED_TIME = tOKEN_EXPIRED_TIME;
	}
    
    private static String JWT_SECRET;
    @Value("${jwt.secret}")
    public void setJWT_SECRET(String jWT_SECRET) {
		JWT_SECRET = jWT_SECRET;
	}
    
    /**
     * 创建JWT
     * @param username
     * @return
     */
    public static String createJWT(String username) {
    	//此处的map是带入到payload中的数据
        Map<String, Object> map = new HashMap<>();
        map.put("username", username);
        //签名的加密算法
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256; 
        //当前时间
        Date now = new Date(System.currentTimeMillis());
        //签名
        SecretKey secretKey = generalKey();
        //下面就是在为payload添加各种标准声明和私有声明了
        JwtBuilder builder = Jwts.builder()
                .setClaims(map)//payload中的额外数据
                .setId((int)(Math.random()*1000000)+"")//设置jti(JWT ID)：是JWT的唯一标识，根据业务需要，这个可以设置为一个不重复的值，主要用来作为一次性token,从而回避重放攻击。
                .setIssuedAt(now)//iat: jwt的签发时间
                .signWith(signatureAlgorithm, secretKey);//设置签名使用的签名算法和签名使用的秘钥
        //过期时间
        long expMillis = now.getTime() + TOKEN_EXPIRED_TIME;
        Date exp = new Date(expMillis);
        //设置过期时间
        builder.setExpiration(exp);
        return builder.compact();
    }


	/**
	 * 验证JWT
	 * @param token
	 * @return
	 */
    public static Claims verifyJwt(String token) {
        //签名秘钥，和生成的签名的秘钥一模一样
        SecretKey key = generalKey();
        Claims claims;
        try {
            claims = Jwts.parser()//得到DefaultJwtParser
                    .setSigningKey(key)//设置签名的秘钥
                    .parseClaimsJws(token).getBody();
        } catch (Exception e) {
        	//校验失败
            claims = null;
        }
        //抛出异常或null均为校验失败
        return claims;

    }


    /**
     * 由字符串生成加密key
     *
     * @return
     */
    public static SecretKey generalKey() {
    	byte[] encodedKey=JWT_SECRET.getBytes();
        SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        return key;
    }

}