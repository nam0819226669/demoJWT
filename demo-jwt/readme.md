# JWT là gì?

**JWT (JSON Web Token)** là một tiêu chuẩn mở được sử dụng để tạo ra và trao đổi các token an toàn và dễ xác thực giữa các bên. JWT được sử dụng rộng rãi trong việc xác thực và ủy quyền trong các ứng dụng web và dịch vụ web.
- **Ưu điểm**
    - **Loại bỏ sự phụ thuộc vào trạng thái (stateless):** JWT là một phương tiện xác thực stateless, nghĩa là không cần lưu trữ trạng thái ở máy chủ. Điều này giảm tải cho máy chủ và giúp mở rộng ứng dụng một cách dễ dàng.
    - **Bảo mật:**
      -   JWT có thể được ký để đảm bảo tính toàn vẹn của dữ liệu. Khi một JWT được ký, máy chủ có thể xác nhận rằng nó chưa được sửa đổi sau khi nó được ký.
      -   Có thể sử dụng cơ chế mã hóa để giữ cho dữ liệu trong JWT được bảo mật và không thể đọc được bởi bên ngoài.
    - **Truyền thông dữ liệu nhỏ gọn:**
      -   JWT là một chuỗi base64 được mã hóa, nên nó làm cho dữ liệu truyền qua mạng trở nên nhỏ gọn hơn so với các phương thức truyền thông tin truyền thống như các phiên cookie.
    - **Phân tán và Hệ thống Microservices:**
      -   JWT cho phép xác thực giữa các dịch vụ khác nhau mà không cần phải lưu trữ trạng thái. Điều này làm cho JWT trở thành một lựa chọn tốt cho các hệ thống phân tán và kiến trúc dựa trên microservices.
    - **Phù hợp với RESTful API:**
      -   JWT được sử dụng rộng rãi trong việc xác thực RESTful API vì tính linh hoạt và dễ sử dụng của nó. Bạn có thể gửi JWT trong tiêu đề HTTP Authorization và kiểm tra nó một cách dễ dàng trên phía máy chủ.
    - **Tích hợp dễ dàng:**
      -   Có nhiều thư viện hỗ trợ JWT trong hầu hết các ngôn ngữ lập trình, làm cho việc triển khai và tích hợp trở nên dễ dàng.
    - **Tùy chỉnh và Mở rộng:**
      -   JWT có thể chứa các trường tùy chỉnh, cho phép bạn lưu trữ thông tin động về người dùng hoặc các quyền truy cập.
- **Nhược điểm**
    - **Không thể hủy bỏ một cách trực tiếp:**
      -   JWT không hỗ trợ cơ chế hủy bỏ trực tiếp. Khi một JWT được phát hành, nó sẽ tồn tại cho đến khi nó hết hạn hoặc được hủy bỏ bởi máy chủ. Điều này có nghĩa là nếu người dùng muốn đăng xuất hoặc bị mất quyền truy cập, không thể hủy bỏ JWT một cách trực tiếp từ phía máy khách. Thay vào đó, bạn phải dựa vào một cơ chế phụ trợ như danh sách đen (blacklist) hoặc thời gian sống ngắn của token để giảm thiểu rủi ro.
    - **Kích thước dữ liệu có thể tăng:**
      -   JWT chứa thông tin về người dùng và các quyền truy cập, nên kích thước của chúng có thể tăng lên khi bạn thêm nhiều thông tin vào trong payload. Điều này có thể gây ra tăng dung lượng dữ liệu truyền qua mạng.
    - **Không thích hợp cho lưu trữ dữ liệu nhạy cảm:**
      -   Mặc dù bạn có thể mã hóa nội dung của JWT để bảo vệ thông tin nhạy cảm, nhưng nó không thích hợp cho việc lưu trữ dữ liệu nhạy cảm. Do dữ liệu trong JWT có thể được giải mã bởi bất kỳ ai có khóa giải mã, nên thông tin nhạy cảm nên được tránh trong JWT nếu có thể.
    - **Không hỗ trợ cơ chế Refresh Token mặc định:**
      -   JWT không cung cấp cơ chế refresh token mặc định. Điều này có nghĩa là bạn phải triển khai một cơ chế riêng biệt để quản lý việc tái tạo token khi nó hết hạn.
    - **Không hỗ trợ cơ chế gửi lại (revoke) hiệu quả:**
      -   Khi sử dụng JWT, việc gửi lại (revoke) token đã phát hành là một thách thức. Mặc dù bạn có thể triển khai một danh sách đen (blacklist) để theo dõi các token đã hủy bỏ, nhưng việc duy trì và quản lý danh sách này có thể là một vấn đề.
## 	Thành phần JWT:

### Header: phần Header sẽ chứa kiểu dữ liệu, và thuật toán sử dụng để mã hoá ra chuỗi JWT.
```json
	 {
		"typ": "JWT",
		"alg": "HS256"
	 }
```
- Payload: phần payload sẽ chứa các thông tin mình muốn đặt trong chuỗi Token.
```json
	{
		"user_name": "admin",
		"user_id": "1513717410",
		"authorities": "ADMIN_USER",
		"jti": "474cb37f-2c9c-44e4-8f5c-1ea5e4cc4d18"
	}
```
- Signature: Phần chữ ký này sẽ được tạo ra bằng cách mã hóa phần header , payload kèm theo một chuỗi secret (khóa bí mật).
```json
			data = base64urlEncode( header ) + "." + base64urlEncode( payload )
			signature = Hash( data, secret ); 
```
##  	Sơ đồ luồng xử lý
![enter image description here](https://images.viblo.asia/bd5688e3-49bc-42cd-956c-79c96d1f5095.png)

- User thực hiện login bằng cách gửi `user/password` hay sử dụng các tài khoản lên phía `Authentication Server` (Server xác thực)
    - `AuthenticationProvider` xử lý các loại xác thực.
        - **authenticate** thực hiện yêu cầu xác thực.
            - Nhận thông tin đăng nhập: `authenticate` nhận thông tin đăng nhập từ Client(user/password, email, ….)
            - Xác thực thông tin: `AuthenticationProvider` sử dụng thông tin tiếp nhận để kiểm tra xem có hợp lệ không. Từ các nguồn với cơ sở dữ liệu, hệ thông LDAP, hoặc các nguồn dữ liệu xác thực khác
            - Trả về `Authentication`: thông tin hợp lệ
        - **supports** kiểm tra xem Server có hỗ trợ loại xác thực hay không.
            - Khi truyền `user/password` thì sẽ sử dụng `UsernamePasswordAuthenticationToken` để đại diện cho thông tin đăng nhập.
            - Khi đó `supports` trong `AuthenticationProvider` sẽ được kiểm tra.
            - `AuthenticationProvider` có hỗ trợ xác thực cho `UsernamePasswordAuthenticationToken` không.
    - Authentication Server tiếp nhận các dữ liệu mà User gửi lên để phục vụ cho việc xác thực người dùng. Khi thành công,
    - Authentication Server sẽ tạo một JWT và trẻ về qua response.
        - `DaoAuthenticationProvider` truy xuất chiết user từ tệp .
    - Khi nhận được JWT do Authentication Sever trả về làm Key để thực hiện các lệnh tiếp theo đối với Application Server.
    - Application Server trước khi thực hiện yêu cầu được gọi từ phía User, sẽ verify JWT gửi lên. Nếu OK, thì thực hiện yêu cầu được gọi.
        - Quy trình thực hiện Verify JWT
        - Chuỗi JWT có cấu trúc H.P.S được Client gửi lên. Server tương tác
            - Set S1 = S
            - Set S2 = HMAC(SHA256(H.P) với secret key của hệ thống)
            - So sánh S1 = S2 ?
        - Nếu S1 và S2 khớp nhau, tức là chữ ký hợp lệ, hệ thống mới tiếp decode payload và tiếp tục kiểm tra các data trong payload.

##	 Luồng xử lý trong Securing Spring Boot with JWT

- Đầu tiên, Client thực hiện gửi request `chứa user/password` lên Server, xin cấp JWT
- Hệ thống thực hiện kiểm tra `user/password`. Khi hợp lệ, hệ thống sinh mã JWT để trả về cho Client thông qua response.
- Client thực hiện lưu Key JWT cho các request tiếp theo. Mỗi request kiểm tra xem có hợp lệ hay không. Nếu hợp lệ thì thực hiện

```json  
package com.nhs3108.services;  
import static java.util.Collections.emptyList;  
public class TokenAuthenticationService {
	static final long EXPIRATIONTIME = 864_000_000; // 10 days
	static final String SECRET = "ThisIsASecret";
	static final String TOKEN_PREFIX = "Bearer";
	static final String HEADER_STRING = "Authorization";
	
	public static void addAuthentication(HttpServletResponse res, String username) {
		String JWT = Jwts.builder()
			.setSubject(username)
			.setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
			.signWith(SignatureAlgorithm.HS256, SECRET)
			.compact();
			res.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + JWT);
	}

	public static Authentication getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(HEADER_STRING);
		if (token != null) {
			Claims claims =  Jwts.parser()
				.setSigningKey(SECRET)
				.parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
				.getBody();
			String username = claims.getSubject();
			Date expDate = claims.getExpiration();
				return user != null ?
				new UsernamePasswordAuthenticationToken(username, null, emptyList()) :
				null;
		}
		return null;
	}
}
```

## Cấu hình và ứng dụng
### 	ADD
- pom.xml
```json
			<dependencies>
				<dependency>
					<groupId>org.springframework.boot</groupId>
					<artifactId>spring-boot-starter-security</artifactId>
				</dependency>
			</dependencies>
```
- .yaml
  - **Cấu hình Secret Key:** JWT cần một secret key để tạo và xác thực token. Bạn có thể cấu hình secret key trong tệp cấu hình của ứng dụng.
  - **Cấu hình Expiration Time:** Bạn có thể cấu hình thời gian hết hạn của token, tức là thời gian sau khi mà token sẽ không còn được chấp nhận nữa.
  - **Cấu hình Algorithm:** JWT hỗ trợ nhiều thuật toán khác nhau cho việc ký và xác thực token. Bạn cần chỉ định thuật toán bạn muốn sử dụng.
  - **Cấu hình Claims:** Bạn có thể cấu hình các claims (thông tin) mà bạn muốn chứa trong token. Ví dụ, thông tin về người dùng hoặc các quyền truy cập.
  - **Cấu hình Token Issuer :** Issuer là một thông tin định danh về người tạo ra token. Bạn có thể cấu hình issuer để xác định người tạo ra token.
```json
		jwt:
			secret: yourSecretKey
			expirationMs: 86400000
			algorithm: HS256
			issuer: yourIssuer
			claims.user-roles: user,admin
```
- SecurityConfig
    -	**Cấu hình Refresh Token:**
         - Triển khai một cơ chế lưu trữ refresh token, chẳng hạn như lưu trữ trong cơ sở dữ liệu.
         - Cấu hình thời gian hết hạn cho refresh token và xác thực khi nó được sử dụng.
    - **Cấu hình Audience:**
        - Cấu hình người nhận token (audience) trong các cấu hình của JWT, nếu cần.
        - Xác thực người nhận token khi xác thực token trong `JwtAuthenticationProvider`.
    - **Cấu hình Not Before:**
        - Sử dụng thư viện JWT để thêm trường thông tin Not Before vào token khi tạo ra.
        - Xác thực thời điểm Not Before khi xác thực token trong `JwtAuthenticationProvider`.
    - **Cấu hình JTI:**
        - Sử dụng thư viện JWT để thêm trường thông tin JTI vào token khi tạo ra.
        - Lưu trữ JTI trong cơ sở dữ liệu và kiểm tra tính duy nhất của JTI khi xác thực token trong `JwtAuthenticationProvider`.
    - **Cấu hình Custom Claims:**
        - Thêm các thông tin tùy chỉnh vào claims khi tạo ra token.
        - Xử lý và xác thực các thông tin tùy chỉnh này khi xác thực token trong `JwtAuthenticationProvider`.

```json
			 protected void configure(HttpSecurity http) throws Exception { 
				 http 
					 .cors() 
					 .and() 
					 .csrf() 
					 .disable(); 
				 for(String url : PUBLIC_URLS) { 
					 http 
						 .authorizeRequests() 
						 .antMatchers(url).permitAll();
				 }  
				http  
					.authorizeRequests()  
					.anyRequest().authenticated();  
				http.addFilterBefore(jwtAuthenticationFilter(),UsernamePasswordAuthenticationFilter.class);  
			}
```
