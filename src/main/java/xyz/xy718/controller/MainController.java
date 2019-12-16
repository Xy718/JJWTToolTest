package xyz.xy718.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Claims;
import xyz.xy718.model.JWTToken;
import xyz.xy718.util.JwtHelper;
import xyz.xy718.util.ResultBean;

@RestController
@RequestMapping("/jwt")
public class MainController {

	@GetMapping("/create")
	public ResultBean createJWT(
			@RequestParam("username")String username
			){
		JWTToken retToken=new JWTToken();
		retToken.setToken(JwtHelper.createJWT(username));
		return ResultBean.success("登录成功",retToken);
	}
	
	@PostMapping("/verify")
	public ResultBean verifyJWT(
			@RequestBody JWTToken token
			){
		Claims claims=JwtHelper.verifyJwt(token.getToken());
		if(claims==null){
			return ResultBean.error("校验失败");
		}
		return ResultBean.success("校验成功",claims);
	} 
}
