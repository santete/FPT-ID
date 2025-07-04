# Hướng dẫn tích hợp OIDC với FPT ID

## 1. Giới thiệu

FPT ID là hệ thống định danh tập trung do FPT xây dựng, sử dụng nền tảng **Ory Hydra** và hỗ trợ giao thức **OpenID Connect (OIDC)** theo chuẩn quốc tế. Việc tích hợp OIDC giúp user đăng nhập qua FPT ID một cách an toàn và chuẩn hóa.

Tài liệu này hướng dẫn user tích hợp nhanh OIDC với domain `https://accounts.fpt.vn` sử dụng thư viện OIDC mới nhất trong các ngôn ngữ phổ biến.

---

## 2. Sơ đồ luồng Authorize Code Flow

graph TD
  A[User mở trang ứng dụng] --> B[Chuyển hướng đến /oauth2/auth]
  B --> C[FPT ID hiển thị màn hình đăng nhập]
  C --> D[User nhập thông tin đăng nhập]
  D --> E[FPT ID xác thực thành công & trả mã code]
  E --> F[Redirect về redirect_uri kèm ?code=...]
  F --> G[Ứng dụng gửi mã code + verifier tới /oauth2/token]
  G --> H[Nhận Access Token, ID Token]
  H --> I[Gọi /userinfo lấy thông tin user]
  I --> J[User đăng nhập vào hệ thống]

> 🔐 Nếu là **Public Client** → bắt buộc sử dụng `code_challenge` và `code_verifier` theo chuẩn **PKCE** để tăng cường bảo mật.

---

## 3. Cấu hình ứng dụng với FPT ID

### ✅ Đăng ký client trên FPT ID Portal:
- Truy cập: [https://accounts.fpt.vn](https://accounts.fpt.vn)
- Cấp: `client_id`, `redirect_uri`
- Tuỳ loại ứng dụng:
  - **Confidential Client (backend/web server)**: cần thêm `client_secret`
  - **Public Client (SPA/mobile)**: **KHÔNG cần `client_secret`**, yêu cầu bật **PKCE**

> 🔐 **Hướng dẫn bật PKCE cho public client:**
> - Khi gọi `/oauth2/auth`, thêm tham số `code_challenge` và `code_challenge_method=S256`.
> - Khi gọi `/oauth2/token`, truyền thêm `code_verifier`.
> - Nhiều thư viện OIDC hiện đại (như `openid-client`, Authlib, AppAuth) sẽ tự xử lý PKCE nếu bạn bật cấu hình tương ứng.

### ✉ Các URL endpoint chuẩn OIDC (dựa trên Ory Hydra):
| Tên | URL |
|------|-----|
| Discovery | `https://accounts.fpt.vn/.well-known/openid-configuration` |
| Authorize | `https://accounts.fpt.vn/oauth2/auth` |
| Token | `https://accounts.fpt.vn/oauth2/token` |
| User Info | `https://accounts.fpt.vn/userinfo` |
| Logout (tùy chọn) | `https://accounts.fpt.vn/oauth2/sessions/logout` |

---

## 4. Tích hợp nhanh theo ngôn ngữ

### 🚀 Node.js (sử dụng `openid-client`)
```bash
npm install openid-client
````

```js
const { Issuer, generators } = require('openid-client');

(async () => {
  const fptIssuer = await Issuer.discover('https://accounts.fpt.vn');
  const client = new fptIssuer.Client({
    client_id: '<YOUR_CLIENT_ID>',
    client_secret: '<YOUR_CLIENT_SECRET>', // Nếu là confidential client
    redirect_uris: ['https://yourapp.com/callback'],
    response_types: ['code']
  });

  const state = generators.state();
  const nonce = generators.nonce();
  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);

  const url = client.authorizationUrl({
    scope: 'openid profile email',
    state,
    nonce,
    code_challenge,
    code_challenge_method: 'S256'
  });

  // Exchange token
  const params = client.callbackParams(req);
  const tokenSet = await client.callback('https://yourapp.com/callback', params, { state, nonce, code_verifier });
  const userinfo = await client.userinfo(tokenSet);
})();
```

---

### 🚀 .NET Core (ASP.NET)

```bash
dotnet add package Microsoft.AspNetCore.Authentication.OpenIdConnect
```

Trong `Program.cs` hoặc `Startup.cs`:

```csharp
builder.Services.AddAuthentication(options => {
    options.DefaultScheme = "Cookies";
    options.DefaultChallengeScheme = "oidc";
})
.AddCookie("Cookies")
.AddOpenIdConnect("oidc", options => {
    options.Authority = "https://accounts.fpt.vn";
    options.ClientId = "<YOUR_CLIENT_ID>";
    options.ClientSecret = "<YOUR_CLIENT_SECRET">; // Confidential client
    options.ResponseType = "code";
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.SaveTokens = true;
    options.UsePkce = true; // Public client nên bật dòng này
});
```

---

### 🚀 Python (Flask - Authlib)

```bash
pip install Authlib Flask
```

```python
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, url_for, session, jsonify

app = Flask(__name__)
app.secret_key = 'secret'
oauth = OAuth(app)

oauth.register(
    name='fptid',
    client_id='YOUR_CLIENT_ID',
    client_secret='YOUR_CLIENT_SECRET',  # Bỏ nếu là public client
    server_metadata_url='https://accounts.fpt.vn/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid profile email',
        'code_challenge_method': 'S256'
    }
)

@app.route('/login')
def login():
    redirect_uri = url_for('auth_callback', _external=True)
    return oauth.fptid.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    token = oauth.fptid.authorize_access_token()
    user = oauth.fptid.parse_id_token(token)
    return jsonify(user)
```

---

## 5. Tips bảo mật khi tích hợp

* Luôn sử dụng HTTPS cho redirect\_uri
* Kiểm tra `state`, `nonce` khi xác thực
* Confidential client: lưu token server-side an toàn
* Public client: luôn bật PKCE, không dùng `client_secret`
* Cập nhật discovery endpoint để lấy JWKS (public key)

---

## 6. Liên hệ hỗ trợ

* Kỹ thuật FPT ID: `fpt.id.support@fpt.com`
* Slack/Teams: Ping @IAM Team hoặc @FPT ID Support

---

## 7. Kết luận

Việc tích hợp FPT ID theo OIDC (Ory Hydra) giúp ứng dụng tuân thủ chuẩn quốc tế và đồng bộ trong hệ sinh thái FPT. Việc sử dụng thư viện chuẩn giúp giảm thiểu sai sót và tối ưu thời gian tích hợp.

Tùy vào loại ứng dụng (confidential vs public client), hãy lựa chọn cấu hình phù hợp và đảm bảo bảo mật theo chuẩn OIDC.
