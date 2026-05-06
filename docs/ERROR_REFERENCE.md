# SaToken Error Reference | 错误参考

**Multi-language Error Documentation**  
**多语言错误文档**

Languages: [English](#english) | [中文](#中文) | [ภาษาไทย](#ภาษาไทย-thai) | [Tiếng Việt](#tiếng-việt-vietnamese) | [ភាសាខ្មែរ](#ភាសាខ្មែរ-khmer) | [Bahasa Melayu](#bahasa-melayu-malay) | [မြန်မာဘာသာ](#မြန်မာဘာသာ-burmese)

---

## English

### Error Categories

sa-token-rust provides 32 error types organized into 10 categories:

#### 1. Basic Token Errors

##### TokenNotFound
- **Message**: "Token not found or expired"
- **Description**: The requested token does not exist in storage or has expired
- **Common Causes**: Token was never created, expired naturally, or manually deleted
- **Solution**: User needs to log in again to obtain a new token

##### InvalidToken
- **Message**: "Token is invalid: {reason}"
- **Description**: The token format or content is invalid
- **Common Causes**: Corrupted token, tampered token, or wrong token format
- **Solution**: Verify token integrity and ensure correct token format

##### TokenExpired
- **Message**: "Token has expired"
- **Description**: The token has passed its expiration time
- **Common Causes**: Token timeout exceeded configured duration
- **Solution**: Use refresh token to get a new access token or re-authenticate

#### 2. Authentication Errors

##### NotLogin
- **Message**: "User not logged in"
- **Description**: User is attempting to access a protected resource without authentication
- **Common Causes**: No token provided, token not found in request
- **Solution**: User must log in first to obtain a valid token

#### 3. Authorization Errors

##### PermissionDenied
- **Message**: "Permission denied: missing permission '{permission}'"
- **Description**: User lacks the required permission to perform the action
- **Common Causes**: Insufficient permissions assigned to the user
- **Solution**: Grant the required permission to the user or role

##### RoleDenied
- **Message**: "Role denied: missing role '{role}'"
- **Description**: User does not have the required role
- **Common Causes**: User not assigned to the necessary role
- **Solution**: Assign the required role to the user

#### 4. Account Status Errors

##### AccountBanned
- **Message**: "Account is banned until {time}"
- **Description**: The account has been temporarily or permanently banned
- **Common Causes**: Violation of terms, security issues, or administrative action
- **Solution**: Wait until ban expires or contact administrator

##### AccountKickedOut
- **Message**: "Account is kicked out"
- **Description**: User session has been forcefully terminated
- **Common Causes**: Administrator kicked the user, concurrent login on another device
- **Solution**: User needs to log in again

#### 5. Session Errors

##### SessionNotFound
- **Message**: "Session not found"
- **Description**: The session does not exist or has been deleted
- **Common Causes**: Session expired, manually deleted, or never created
- **Solution**: Establish a new session by logging in

#### 6. Nonce Errors

##### NonceAlreadyUsed
- **Message**: "Nonce has been used, possible replay attack detected"
- **Description**: The nonce has already been consumed, indicating a potential replay attack
- **Common Causes**: Duplicate request submission, replay attack attempt
- **Solution**: Generate a new nonce for each request

##### InvalidNonceFormat
- **Message**: "Invalid nonce format"
- **Description**: The nonce does not follow the expected format
- **Common Causes**: Corrupted nonce, manually crafted invalid nonce
- **Solution**: Use the standard nonce generation method

##### InvalidNonceTimestamp
- **Message**: "Nonce timestamp is invalid or expired"
- **Description**: The timestamp embedded in the nonce is invalid or outside the valid time window
- **Common Causes**: System time drift, expired nonce, or tampered timestamp
- **Solution**: Synchronize system time and generate a fresh nonce

#### 7. Refresh Token Errors

##### RefreshTokenNotFound
- **Message**: "Refresh token not found or expired"
- **Description**: The refresh token does not exist or has expired
- **Common Causes**: Never issued, expired, or revoked
- **Solution**: User must re-authenticate to get a new refresh token

##### RefreshTokenInvalidData
- **Message**: "Invalid refresh token data"
- **Description**: The stored refresh token data is corrupted or malformed
- **Common Causes**: Storage corruption, tampering, or serialization error
- **Solution**: User must re-authenticate

##### RefreshTokenMissingLoginId
- **Message**: "Missing login_id in refresh token"
- **Description**: The refresh token is missing the required login_id field
- **Common Causes**: Data corruption or incomplete token generation
- **Solution**: Generate a new refresh token

##### RefreshTokenInvalidExpireTime
- **Message**: "Invalid expire time format in refresh token"
- **Description**: The expiration time in refresh token cannot be parsed
- **Common Causes**: Incorrect date format or corrupted data
- **Solution**: Generate a new refresh token with correct format

#### 8. Token Validation Errors

##### TokenEmpty
- **Message**: "Token is empty"
- **Description**: No token value provided
- **Common Causes**: Empty string passed as token
- **Solution**: Provide a valid token value

##### TokenTooShort
- **Message**: "Token is too short"
- **Description**: Token length is below minimum required (8 characters)
- **Common Causes**: Truncated or invalid token
- **Solution**: Provide a complete valid token

##### LoginIdNotNumber
- **Message**: "Login ID is not a valid number"
- **Description**: Failed to parse login ID as a numeric value
- **Common Causes**: Non-numeric login ID when numeric is expected
- **Solution**: Ensure login ID format matches expected type

#### 9. OAuth2 Errors

##### OAuth2ClientNotFound
- **Message**: "OAuth2 client not found"
- **Description**: The OAuth2 client ID does not exist
- **Common Causes**: Unregistered client or incorrect client ID
- **Solution**: Register the client or verify client ID

##### OAuth2InvalidCredentials
- **Message**: "Invalid client credentials"
- **Description**: Client ID and secret combination is invalid
- **Common Causes**: Wrong secret, mistyped credentials
- **Solution**: Verify client credentials are correct

##### OAuth2ClientIdMismatch
- **Message**: "Client ID mismatch"
- **Description**: Client ID doesn't match the expected value
- **Common Causes**: Using wrong client ID for authorization code or refresh token
- **Solution**: Use the correct client ID that initiated the flow

##### OAuth2RedirectUriMismatch
- **Message**: "Redirect URI mismatch"
- **Description**: Redirect URI doesn't match registered URIs
- **Common Causes**: URI not in whitelist, typo in URI
- **Solution**: Use a registered redirect URI

##### OAuth2CodeNotFound
- **Message**: "Authorization code not found or expired"
- **Description**: Authorization code doesn't exist or has expired
- **Common Causes**: Code already used, expired (typically 10 minutes)
- **Solution**: Request a new authorization code

##### OAuth2AccessTokenNotFound
- **Message**: "Access token not found or expired"
- **Description**: OAuth2 access token not found or expired
- **Common Causes**: Token expired (typically 1 hour), revoked, or never issued
- **Solution**: Refresh token or re-authorize

##### OAuth2RefreshTokenNotFound
- **Message**: "Refresh token not found or expired"
- **Description**: OAuth2 refresh token not found or expired
- **Common Causes**: Token expired (typically 30 days), revoked, or never issued
- **Solution**: User must re-authorize

##### OAuth2InvalidRefreshToken
- **Message**: "Invalid refresh token data"
- **Description**: Refresh token data is corrupted or invalid
- **Common Causes**: Data corruption, tampering
- **Solution**: Re-authorize to get new tokens

##### OAuth2InvalidScope
- **Message**: "Invalid scope data"
- **Description**: Scope data is invalid or corrupted
- **Common Causes**: Invalid scope format, unauthorized scope request
- **Solution**: Request valid scopes only

#### 10. System Errors

##### StorageError
- **Message**: "Storage error: {details}"
- **Description**: Error occurred while accessing storage backend
- **Common Causes**: Database connection failure, Redis unavailable, network issues
- **Solution**: Check storage backend status and connectivity

##### ConfigError
- **Message**: "Configuration error: {details}"
- **Description**: Configuration is invalid or missing
- **Common Causes**: Missing required config, invalid config values
- **Solution**: Review and fix configuration

##### SerializationError
- **Message**: "Serialization error: {details}"
- **Description**: Failed to serialize or deserialize data
- **Common Causes**: Data structure mismatch, corrupted JSON
- **Solution**: Check data format and structure

##### InternalError
- **Message**: "Internal error: {details}"
- **Description**: An unexpected internal error occurred
- **Common Causes**: Programming error, unexpected state
- **Solution**: Report to developers with error details

---

## 中文

### 错误分类

sa-token-rust 提供了 32 种错误类型，分为 10 个类别：

#### 1. 基础 Token 错误

##### TokenNotFound
- **消息**：Token 未找到或已过期
- **描述**：请求的 Token 在存储中不存在或已过期
- **常见原因**：Token 从未创建、自然过期或被手动删除
- **解决方案**：用户需要重新登录以获取新的 Token

##### InvalidToken
- **消息**：Token 无效：{原因}
- **描述**：Token 格式或内容无效
- **常见原因**：Token 损坏、被篡改或格式错误
- **解决方案**：验证 Token 完整性并确保格式正确

##### TokenExpired
- **消息**：Token 已过期
- **描述**：Token 已超过其有效期
- **常见原因**：Token 超时超过配置的持续时间
- **解决方案**：使用刷新令牌获取新的访问令牌或重新认证

#### 2. 认证错误

##### NotLogin
- **消息**：用户未登录
- **描述**：用户试图在未认证的情况下访问受保护的资源
- **常见原因**：未提供 Token，请求中找不到 Token
- **解决方案**：用户必须先登录以获取有效的 Token

#### 3. 授权错误

##### PermissionDenied
- **消息**：权限被拒绝：缺少权限 '{权限}'
- **描述**：用户缺少执行该操作所需的权限
- **常见原因**：用户权限不足
- **解决方案**：为用户或角色授予所需权限

##### RoleDenied
- **消息**：角色被拒绝：缺少角色 '{角色}'
- **描述**：用户没有所需的角色
- **常见原因**：用户未被分配到必要的角色
- **解决方案**：为用户分配所需角色

#### 4. 账户状态错误

##### AccountBanned
- **消息**：账户被封禁至 {时间}
- **描述**：账户已被临时或永久封禁
- **常见原因**：违反条款、安全问题或管理员操作
- **解决方案**：等待封禁到期或联系管理员

##### AccountKickedOut
- **消息**：账户被踢出
- **描述**：用户会话已被强制终止
- **常见原因**：管理员踢出用户、在其他设备上并发登录
- **解决方案**：用户需要重新登录

#### 5. Session 错误

##### SessionNotFound
- **消息**：Session 未找到
- **描述**：会话不存在或已被删除
- **常见原因**：会话过期、被手动删除或从未创建
- **解决方案**：通过登录建立新会话

#### 6. Nonce 错误

##### NonceAlreadyUsed
- **消息**：Nonce 已被使用，可能检测到重放攻击
- **描述**：Nonce 已被消费，表明可能存在重放攻击
- **常见原因**：重复提交请求、重放攻击尝试
- **解决方案**：为每个请求生成新的 Nonce

##### InvalidNonceFormat
- **消息**：无效的 Nonce 格式
- **描述**：Nonce 不符合预期格式
- **常见原因**：Nonce 损坏、手动构造的无效 Nonce
- **解决方案**：使用标准的 Nonce 生成方法

##### InvalidNonceTimestamp
- **消息**：Nonce 时间戳无效或已过期
- **描述**：Nonce 中嵌入的时间戳无效或超出有效时间窗口
- **常见原因**：系统时间偏移、Nonce 过期或时间戳被篡改
- **解决方案**：同步系统时间并生成新的 Nonce

#### 7. 刷新令牌错误

##### RefreshTokenNotFound
- **消息**：刷新令牌未找到或已过期
- **描述**：刷新令牌不存在或已过期
- **常见原因**：从未发行、已过期或已撤销
- **解决方案**：用户必须重新认证以获取新的刷新令牌

##### RefreshTokenInvalidData
- **消息**：无效的刷新令牌数据
- **描述**：存储的刷新令牌数据已损坏或格式错误
- **常见原因**：存储损坏、篡改或序列化错误
- **解决方案**：用户必须重新认证

##### RefreshTokenMissingLoginId
- **消息**：刷新令牌中缺少 login_id
- **描述**：刷新令牌缺少必需的 login_id 字段
- **常见原因**：数据损坏或令牌生成不完整
- **解决方案**：生成新的刷新令牌

##### RefreshTokenInvalidExpireTime
- **消息**：刷新令牌中的过期时间格式无效
- **描述**：刷新令牌中的过期时间无法解析
- **常见原因**：日期格式不正确或数据损坏
- **解决方案**：生成格式正确的新刷新令牌

#### 8. Token 验证错误

##### TokenEmpty
- **消息**：Token 为空
- **描述**：未提供 Token 值
- **常见原因**：传递了空字符串作为 Token
- **解决方案**：提供有效的 Token 值

##### TokenTooShort
- **消息**：Token 太短
- **描述**：Token 长度低于最小要求（8 个字符）
- **常见原因**：被截断或无效的 Token
- **解决方案**：提供完整有效的 Token

##### LoginIdNotNumber
- **消息**：登录 ID 不是有效数字
- **描述**：无法将登录 ID 解析为数值
- **常见原因**：当期望数字时提供了非数字登录 ID
- **解决方案**：确保登录 ID 格式与预期类型匹配

#### 9. OAuth2 错误

##### OAuth2ClientNotFound
- **消息**：OAuth2 客户端未找到
- **描述**：OAuth2 客户端 ID 不存在
- **常见原因**：未注册的客户端或客户端 ID 错误
- **解决方案**：注册客户端或验证客户端 ID

##### OAuth2InvalidCredentials
- **消息**：无效的客户端凭据
- **描述**：客户端 ID 和密钥组合无效
- **常见原因**：密钥错误、凭据输入错误
- **解决方案**：验证客户端凭据是否正确

##### OAuth2ClientIdMismatch
- **消息**：客户端 ID 不匹配
- **描述**：客户端 ID 与预期值不匹配
- **常见原因**：为授权码或刷新令牌使用了错误的客户端 ID
- **解决方案**：使用发起流程的正确客户端 ID

##### OAuth2RedirectUriMismatch
- **消息**：重定向 URI 不匹配
- **描述**：重定向 URI 与注册的 URI 不匹配
- **常见原因**：URI 不在白名单中、URI 拼写错误
- **解决方案**：使用已注册的重定向 URI

##### OAuth2CodeNotFound
- **消息**：授权码未找到或已过期
- **描述**：授权码不存在或已过期
- **常见原因**：授权码已使用、已过期（通常 10 分钟）
- **解决方案**：请求新的授权码

##### OAuth2AccessTokenNotFound
- **消息**：访问令牌未找到或已过期
- **描述**：OAuth2 访问令牌未找到或已过期
- **常见原因**：令牌过期（通常 1 小时）、已撤销或从未发行
- **解决方案**：刷新令牌或重新授权

##### OAuth2RefreshTokenNotFound
- **消息**：刷新令牌未找到或已过期
- **描述**：OAuth2 刷新令牌未找到或已过期
- **常见原因**：令牌过期（通常 30 天）、已撤销或从未发行
- **解决方案**：用户必须重新授权

##### OAuth2InvalidRefreshToken
- **消息**：无效的刷新令牌数据
- **描述**：刷新令牌数据已损坏或无效
- **常见原因**：数据损坏、篡改
- **解决方案**：重新授权以获取新令牌

##### OAuth2InvalidScope
- **消息**：无效的权限范围数据
- **描述**：权限范围数据无效或已损坏
- **常见原因**：权限范围格式无效、未授权的权限范围请求
- **解决方案**：仅请求有效的权限范围

#### 10. 系统错误

##### StorageError
- **消息**：存储错误：{详情}
- **描述**：访问存储后端时发生错误
- **常见原因**：数据库连接失败、Redis 不可用、网络问题
- **解决方案**：检查存储后端状态和连接性

##### ConfigError
- **消息**：配置错误：{详情}
- **描述**：配置无效或缺失
- **常见原因**：缺少必需配置、配置值无效
- **解决方案**：审查并修复配置

##### SerializationError
- **消息**：序列化错误：{详情}
- **描述**：序列化或反序列化数据失败
- **常见原因**：数据结构不匹配、JSON 损坏
- **解决方案**：检查数据格式和结构

##### InternalError
- **消息**：内部错误：{详情}
- **描述**：发生意外的内部错误
- **常见原因**：编程错误、意外状态
- **解决方案**：向开发人员报告错误详情

---

## ภาษาไทย (Thai)

### หมวดหมู่ข้อผิดพลาด

sa-token-rust มีประเภทข้อผิดพลาด 32 ประเภท แบ่งเป็น 10 หมวดหมู่:

#### 1. ข้อผิดพลาดโทเค็นพื้นฐาน

##### TokenNotFound
- **ข้อความ**: "ไม่พบโทเค็นหรือหมดอายุแล้ว"
- **คำอธิบาย**: โทเค็นที่ร้องขอไม่มีอยู่ในระบบหรือหมดอายุแล้ว
- **สาเหตุทั่วไป**: โทเค็นไม่เคยถูกสร้าง หมดอายุตามธรรมชาติ หรือถูกลบด้วยตนเอง
- **วิธีแก้ไข**: ผู้ใช้ต้องเข้าสู่ระบบใหม่เพื่อรับโทเค็นใหม่

##### InvalidToken
- **ข้อความ**: "โทเค็นไม่ถูกต้อง: {เหตุผล}"
- **คำอธิบาย**: รูปแบบหรือเนื้อหาของโทเค็นไม่ถูกต้อง
- **สาเหตุทั่วไป**: โทเค็นเสียหาย ถูกปลอมแปลง หรือรูปแบบไม่ถูกต้อง
- **วิธีแก้ไข**: ตรวจสอบความสมบูรณ์ของโทเค็นและให้แน่ใจว่ารูปแบบถูกต้อง

##### TokenExpired
- **ข้อความ**: "โทเค็นหมดอายุแล้ว"
- **คำอธิบาย**: โทเค็นเกินกำหนดเวลาที่ตั้งไว้
- **สาเหตุทั่วไป**: เวลาโทเค็นเกินระยะเวลาที่กำหนดค่าไว้
- **วิธีแก้ไข**: ใช้โทเค็นรีเฟรชเพื่อรับโทเค็นเข้าถึงใหม่หรือตรวจสอบสิทธิ์ใหม่

#### 2. ข้อผิดพลาดการตรวจสอบสิทธิ์

##### NotLogin
- **ข้อความ**: "ผู้ใช้ยังไม่ได้เข้าสู่ระบบ"
- **คำอธิบาย**: ผู้ใช้พยายามเข้าถึงทรัพยากรที่ได้รับการป้องกันโดยไม่มีการตรวจสอบสิทธิ์
- **สาเหตุทั่วไป**: ไม่มีโทเค็น ไม่พบโทเค็นในคำขอ
- **วิธีแก้ไข**: ผู้ใช้ต้องเข้าสู่ระบบก่อนเพื่อรับโทเค็นที่ถูกต้อง

#### 3. ข้อผิดพลาดการอนุญาต

##### PermissionDenied
- **ข้อความ**: "ปฏิเสธการอนุญาต: ขาดสิทธิ์ '{สิทธิ์}'"
- **คำอธิบาย**: ผู้ใช้ขาดสิทธิ์ที่จำเป็นในการดำเนินการ
- **สาเหตุทั่วไป**: สิทธิ์ไม่เพียงพอที่กำหนดให้กับผู้ใช้
- **วิธีแก้ไข**: ให้สิทธิ์ที่จำเป็นแก่ผู้ใช้หรือบทบาท

##### RoleDenied
- **ข้อความ**: "ปฏิเสธบทบาท: ขาดบทบาท '{บทบาท}'"
- **คำอธิบาย**: ผู้ใช้ไม่มีบทบาทที่จำเป็น
- **สาเหตุทั่วไป**: ผู้ใช้ไม่ได้รับมอบหมายบทบาทที่จำเป็น
- **วิธีแก้ไข**: กำหนดบทบาทที่จำเป็นให้กับผู้ใช้

#### 4. ข้อผิดพลาดสถานะบัญชี

##### AccountBanned
- **ข้อความ**: "บัญชีถูกระงับจนถึง {เวลา}"
- **คำอธิบาย**: บัญชีถูกระงับชั่วคราวหรือถาวร
- **สาเหตุทั่วไป**: ละเมิดข้อกำหนด ปัญหาความปลอดภัย หรือการดำเนินการของผู้ดูแลระบบ
- **วิธีแก้ไข**: รอจนกว่าการระงับจะหมดอายุหรือติดต่อผู้ดูแลระบบ

##### AccountKickedOut
- **ข้อความ**: "บัญชีถูกไล่ออก"
- **คำอธิบาย**: เซสชันของผู้ใช้ถูกยกเลิกอย่างบังคับ
- **สาเหตุทั่วไป**: ผู้ดูแลระบบไล่ผู้ใช้ออก การเข้าสู่ระบบพร้อมกันบนอุปกรณ์อื่น
- **วิธีแก้ไข**: ผู้ใช้ต้องเข้าสู่ระบบใหม่

#### 5. ข้อผิดพลาดเซสชัน

##### SessionNotFound
- **ข้อความ**: "ไม่พบเซสชัน"
- **คำอธิบาย**: เซสชันไม่มีอยู่หรือถูกลบแล้ว
- **สาเหตุทั่วไป**: เซสชันหมดอายุ ถูกลบด้วยตนเอง หรือไม่เคยสร้าง
- **วิธีแก้ไข**: สร้างเซสชันใหม่โดยการเข้าสู่ระบบ

#### 6. ข้อผิดพลาด Nonce

##### NonceAlreadyUsed
- **ข้อความ**: "Nonce ถูกใช้แล้ว อาจตรวจพบการโจมตีแบบ replay"
- **คำอธิบาย**: Nonce ถูกใช้แล้ว บ่งชี้ว่าอาจมีการโจมตีแบบ replay
- **สาเหตุทั่วไป**: ส่งคำขอซ้ำ พยายามโจมตีแบบ replay
- **วิธีแก้ไข**: สร้าง Nonce ใหม่สำหรับแต่ละคำขอ

##### InvalidNonceFormat
- **ข้อความ**: "รูปแบบ Nonce ไม่ถูกต้อง"
- **คำอธิบาย**: Nonce ไม่ตรงตามรูปแบบที่คาดหวัง
- **สาเหตุทั่วไป**: Nonce เสียหาย Nonce ไม่ถูกต้องที่สร้างด้วยตนเอง
- **วิธีแก้ไข**: ใช้วิธีการสร้าง Nonce มาตรฐาน

##### InvalidNonceTimestamp
- **ข้อความ**: "ประทับเวลา Nonce ไม่ถูกต้องหรือหมดอายุ"
- **คำอธิบาย**: ประทับเวลาที่ฝังใน Nonce ไม่ถูกต้องหรือนอกช่วงเวลาที่ถูกต้อง
- **สาเหตุทั่วไป**: เวลาระบบคลาดเคลื่อน Nonce หมดอายุ หรือประทับเวลาถูกปลอมแปลง
- **วิธีแก้ไข**: ซิงโครไนซ์เวลาระบบและสร้าง Nonce ใหม่

#### 7. ข้อผิดพลาดโทเค็นรีเฟรช

##### RefreshTokenNotFound
- **ข้อความ**: "ไม่พบโทเค็นรีเฟรชหรือหมดอายุแล้ว"
- **คำอธิบาย**: โทเค็นรีเฟรชไม่มีอยู่หรือหมดอายุแล้ว
- **สาเหตุทั่วไป**: ไม่เคยออก หมดอายุ หรือถูกเพิกถอน
- **วิธีแก้ไข**: ผู้ใช้ต้องตรวจสอบสิทธิ์ใหม่เพื่อรับโทเค็นรีเฟรชใหม่

##### RefreshTokenInvalidData
- **ข้อความ**: "ข้อมูลโทเค็นรีเฟรชไม่ถูกต้อง"
- **คำอธิบาย**: ข้อมูลโทเค็นรีเฟรชที่เก็บไว้เสียหายหรือรูปแบบไม่ถูกต้อง
- **สาเหตุทั่วไป**: การเก็บข้อมูลเสียหาย การปลอมแปลง หรือข้อผิดพลาดในการทำให้เป็นอนุกรม
- **วิธีแก้ไข**: ผู้ใช้ต้องตรวจสอบสิทธิ์ใหม่

#### 8. ข้อผิดพลาดการตรวจสอบโทเค็น

##### TokenEmpty
- **ข้อความ**: "โทเค็นว่างเปล่า"
- **คำอธิบาย**: ไม่มีค่าโทเค็น
- **สาเหตุทั่วไป**: ส่งสตริงว่างเปล่าเป็นโทเค็น
- **วิธีแก้ไข**: ให้ค่าโทเค็นที่ถูกต้อง

##### TokenTooShort
- **ข้อความ**: "โทเค็นสั้นเกินไป"
- **คำอธิบาย**: ความยาวโทเค็นต่ำกว่าขั้นต่ำที่กำหนด (8 ตัวอักษร)
- **สาเหตุทั่วไป**: โทเค็นถูกตัดทอนหรือไม่ถูกต้อง
- **วิธีแก้ไข**: ให้โทเค็นที่สมบูรณ์และถูกต้อง

#### 9. ข้อผิดพลาด OAuth2

##### OAuth2ClientNotFound
- **ข้อความ**: "ไม่พบไคลเอนต์ OAuth2"
- **คำอธิบาย**: ID ไคลเอนต์ OAuth2 ไม่มีอยู่
- **สาเหตุทั่วไป**: ไคลเอนต์ที่ไม่ได้ลงทะเบียนหรือ ID ไคลเอนต์ไม่ถูกต้อง
- **วิธีแก้ไข**: ลงทะเบียนไคลเอนต์หรือตรวจสอบ ID ไคลเอนต์

#### 10. ข้อผิดพลาดระบบ

##### StorageError
- **ข้อความ**: "ข้อผิดพลาดการจัดเก็บ: {รายละเอียด}"
- **คำอธิบาย**: เกิดข้อผิดพลาดขณะเข้าถึงระบบจัดเก็บ
- **สาเหตุทั่วไป**: การเชื่อมต่อฐานข้อมูลล้มเหลว Redis ไม่พร้อมใช้งาน ปัญหาเครือข่าย
- **วิธีแก้ไข**: ตรวจสอบสถานะและการเชื่อมต่อของระบบจัดเก็บ

---

## Tiếng Việt (Vietnamese)

### Danh mục lỗi

sa-token-rust cung cấp 32 loại lỗi được tổ chức thành 10 danh mục:

#### 1. Lỗi Token cơ bản

##### TokenNotFound
- **Thông báo**: "Không tìm thấy token hoặc đã hết hạn"
- **Mô tả**: Token được yêu cầu không tồn tại trong bộ nhớ hoặc đã hết hạn
- **Nguyên nhân thường gặp**: Token chưa từng được tạo, hết hạn tự nhiên, hoặc bị xóa thủ công
- **Giải pháp**: Người dùng cần đăng nhập lại để lấy token mới

##### InvalidToken
- **Thông báo**: "Token không hợp lệ: {lý do}"
- **Mô tả**: Định dạng hoặc nội dung token không hợp lệ
- **Nguyên nhân thường gặp**: Token bị hỏng, bị giả mạo, hoặc định dạng sai
- **Giải pháp**: Xác minh tính toàn vẹn của token và đảm bảo định dạng đúng

##### TokenExpired
- **Thông báo**: "Token đã hết hạn"
- **Mô tả**: Token đã quá thời gian hết hạn
- **Nguyên nhân thường gặp**: Thời gian chờ token vượt quá thời lượng đã cấu hình
- **Giải pháp**: Sử dụng refresh token để lấy access token mới hoặc xác thực lại

#### 2. Lỗi xác thực

##### NotLogin
- **Thông báo**: "Người dùng chưa đăng nhập"
- **Mô tả**: Người dùng đang cố gắng truy cập tài nguyên được bảo vệ mà không có xác thực
- **Nguyên nhân thường gặp**: Không có token, không tìm thấy token trong yêu cầu
- **Giải pháp**: Người dùng phải đăng nhập trước để có token hợp lệ

#### 3. Lỗi ủy quyền

##### PermissionDenied
- **Thông báo**: "Quyền bị từ chối: thiếu quyền '{quyền}'"
- **Mô tả**: Người dùng thiếu quyền cần thiết để thực hiện hành động
- **Nguyên nhân thường gặp**: Quyền được cấp cho người dùng không đủ
- **Giải pháp**: Cấp quyền cần thiết cho người dùng hoặc vai trò

##### RoleDenied
- **Thông báo**: "Vai trò bị từ chối: thiếu vai trò '{vai trò}'"
- **Mô tả**: Người dùng không có vai trò cần thiết
- **Nguyên nhân thường gặp**: Người dùng không được gán vai trò cần thiết
- **Giải pháp**: Gán vai trò cần thiết cho người dùng

#### 4. Lỗi trạng thái tài khoản

##### AccountBanned
- **Thông báo**: "Tài khoản bị cấm đến {thời gian}"
- **Mô tả**: Tài khoản đã bị cấm tạm thời hoặc vĩnh viễn
- **Nguyên nhân thường gặp**: Vi phạm điều khoản, vấn đề bảo mật, hoặc hành động của quản trị viên
- **Giải pháp**: Đợi đến khi hết lệnh cấm hoặc liên hệ quản trị viên

##### AccountKickedOut
- **Thông báo**: "Tài khoản bị đá ra"
- **Mô tả**: Phiên của người dùng đã bị chấm dứt cưỡng bức
- **Nguyên nhân thường gặp**: Quản trị viên đá người dùng ra, đăng nhập đồng thời trên thiết bị khác
- **Giải pháp**: Người dùng cần đăng nhập lại

#### 5. Lỗi phiên

##### SessionNotFound
- **Thông báo**: "Không tìm thấy phiên"
- **Mô tả**: Phiên không tồn tại hoặc đã bị xóa
- **Nguyên nhân thường gặp**: Phiên hết hạn, bị xóa thủ công, hoặc chưa từng được tạo
- **Giải pháp**: Tạo phiên mới bằng cách đăng nhập

#### 6. Lỗi Nonce

##### NonceAlreadyUsed
- **Thông báo**: "Nonce đã được sử dụng, phát hiện khả năng tấn công replay"
- **Mô tả**: Nonce đã được tiêu thụ, cho thấy có thể có cuộc tấn công replay
- **Nguyên nhân thường gặp**: Gửi yêu cầu trùng lặp, cố gắng tấn công replay
- **Giải pháp**: Tạo nonce mới cho mỗi yêu cầu

##### InvalidNonceFormat
- **Thông báo**: "Định dạng nonce không hợp lệ"
- **Mô tả**: Nonce không tuân theo định dạng mong đợi
- **Nguyên nhân thường gặp**: Nonce bị hỏng, nonce không hợp lệ được tạo thủ công
- **Giải pháp**: Sử dụng phương thức tạo nonce tiêu chuẩn

##### InvalidNonceTimestamp
- **Thông báo**: "Dấu thời gian nonce không hợp lệ hoặc đã hết hạn"
- **Mô tả**: Dấu thời gian nhúng trong nonce không hợp lệ hoặc nằm ngoài cửa sổ thời gian hợp lệ
- **Nguyên nhân thường gặp**: Thời gian hệ thống trôi dạt, nonce hết hạn, hoặc dấu thời gian bị giả mạo
- **Giải pháp**: Đồng bộ thời gian hệ thống và tạo nonce mới

#### 7. Lỗi Refresh Token

##### RefreshTokenNotFound
- **Thông báo**: "Không tìm thấy refresh token hoặc đã hết hạn"
- **Mô tả**: Refresh token không tồn tại hoặc đã hết hạn
- **Nguyên nhân thường gặp**: Chưa từng được phát hành, hết hạn, hoặc bị thu hồi
- **Giải pháp**: Người dùng phải xác thực lại để lấy refresh token mới

##### RefreshTokenInvalidData
- **Thông báo**: "Dữ liệu refresh token không hợp lệ"
- **Mô tả**: Dữ liệu refresh token được lưu trữ bị hỏng hoặc sai định dạng
- **Nguyên nhân thường gặp**: Bộ nhớ bị hỏng, giả mạo, hoặc lỗi tuần tự hóa
- **Giải pháp**: Người dùng phải xác thực lại

#### 8. Lỗi xác thực Token

##### TokenEmpty
- **Thông báo**: "Token trống"
- **Mô tả**: Không có giá trị token được cung cấp
- **Nguyên nhân thường gặp**: Chuỗi trống được truyền làm token
- **Giải pháp**: Cung cấp giá trị token hợp lệ

##### TokenTooShort
- **Thông báo**: "Token quá ngắn"
- **Mô tả**: Độ dài token dưới mức tối thiểu yêu cầu (8 ký tự)
- **Nguyên nhân thường gặp**: Token bị cắt ngắn hoặc không hợp lệ
- **Giải pháp**: Cung cấp token hợp lệ đầy đủ

#### 9. Lỗi OAuth2

##### OAuth2ClientNotFound
- **Thông báo**: "Không tìm thấy client OAuth2"
- **Mô tả**: ID client OAuth2 không tồn tại
- **Nguyên nhân thường gặp**: Client chưa đăng ký hoặc ID client sai
- **Giải pháp**: Đăng ký client hoặc xác minh ID client

#### 10. Lỗi hệ thống

##### StorageError
- **Thông báo**: "Lỗi lưu trữ: {chi tiết}"
- **Mô tả**: Xảy ra lỗi khi truy cập backend lưu trữ
- **Nguyên nhân thường gặp**: Kết nối cơ sở dữ liệu thất bại, Redis không khả dụng, vấn đề mạng
- **Giải pháp**: Kiểm tra trạng thái và kết nối của backend lưu trữ

---

## ភាសាខ្មែរ (Khmer)

### ប្រភេទកំហុស

sa-token-rust ផ្តល់នូវប្រភេទកំហុសចំនួន 32 ដែលរៀបចំជា 10 ប្រភេទ:

#### 1. កំហុសថូខឹនមូលដ្ឋាន

##### TokenNotFound
- **សារ**: "រកមិនឃើញថូខឹនឬផុតកំណត់"
- **ការពិពណ៌នា**: ថូខឹនដែលស្នើសុំមិនមាននៅក្នុងឃ្លាំងសារពត៌មានឬផុតកំណត់
- **មូលហេតុទូទៅ**: ថូខឹនមិនធ្លាប់ត្រូវបានបង្កើត ផុតកំណត់ដោយធម្មជាតិ ឬត្រូវបានលុបដោយដៃ
- **ដំណោះស្រាយ**: អ្នកប្រើប្រាស់ត្រូវតែចូលម្តងទៀតដើម្បីទទួលបានថូខឹនថ្មី

##### InvalidToken
- **សារ**: "ថូខឹនមិនត្រឹមត្រូវ: {ហេតុផល}"
- **ការពិពណ៌នា**: ទម្រង់ឬមាតិកាថូខឹនមិនត្រឹមត្រូវ
- **មូលហេតុទូទៅ**: ថូខឹនខូច ត្រូវបានធ្វើឱ្យប្លែក ឬទម្រង់មិនត្រឹមត្រូវ
- **ដំណោះស្រាយ**: ពិនិត្យភាពគ្រប់លក្ខណ៍នៃថូខឹននិងធានាថាទម្រង់ត្រឹមត្រូវ

##### TokenExpired
- **សារ**: "ថូខឹនផុតកំណត់"
- **ការពិពណ៌នា**: ថូខឹនបានហួសពេលផុតកំណត់របស់វា
- **មូលហេតុទូទៅ**: ថូខឹនលើសពីរយៈពេលដែលបានកំណត់
- **ដំណោះស្រាយ**: ប្រើថូខឹនធ្វើឱ្យស្រស់ដើម្បីទទួលបានថូខឹនចូលប្រើថ្មីឬផ្ទៀងផ្ទាត់ម្តងទៀត

#### 2. កំហុសការផ្ទៀងផ្ទាត់

##### NotLogin
- **សារ**: "អ្នកប្រើប្រាស់មិនទាន់ចូល"
- **ការពិពណ៌នា**: អ្នកប្រើប្រាស់កំពុងព្យាយាមចូលប្រើធនធានដែលត្រូវបានការពារដោយគ្មានការផ្ទៀងផ្ទាត់
- **មូលហេតុទូទៅ**: គ្មានថូខឹន រកមិនឃើញថូខឹនក្នុងសំណើ
- **ដំណោះស្រាយ**: អ្នកប្រើប្រាស់ត្រូវតែចូលជាមុនដើម្បីទទួលបានថូខឹនដែលត្រឹមត្រូវ

#### 3. កំហុសការអនុញ្ញាត

##### PermissionDenied
- **សារ**: "បដិសេធការអនុញ្ញាត: ខ្វះការអនុញ្ញាត '{ការអនុញ្ញាត}'"
- **ការពិពណ៌នា**: អ្នកប្រើប្រាស់ខ្វះការអនុញ្ញាតចាំបាច់ដើម្បីអនុវត្តសកម្មភាព
- **មូលហេតុទូទៅ**: ការអនុញ្ញាតមិនគ្រប់គ្រាន់ដែលបានកំណត់ដល់អ្នកប្រើប្រាស់
- **ដំណោះស្រាយ**: ផ្តល់ការអនុញ្ញាតចាំបាច់ដល់អ្នកប្រើប្រាស់ឬតួនាទី

##### RoleDenied
- **សារ**: "បដិសេធតួនាទី: ខ្វះតួនាទី '{តួនាទី}'"
- **ការពិពណ៌នា**: អ្នកប្រើប្រាស់មិនមានតួនាទីចាំបាច់
- **មូលហេតុទូទៅ**: អ្នកប្រើប្រាស់មិនត្រូវបានកំណត់ដល់តួនាទីចាំបាច់
- **ដំណោះស្រាយ**: កំណត់តួនាទីចាំបាច់ដល់អ្នកប្រើប្រាស់

#### 4. កំហុសស្ថានភាពគណនី

##### AccountBanned
- **សារ**: "គណនីត្រូវបានហាមឃាត់រហូតដល់ {ពេលវេលា}"
- **ការពិពណ៌នា**: គណនីត្រូវបានហាមឃាត់ជាបណ្តោះអាសន្នឬអចិន្ត្រៃយ៍
- **មូលហេតុទូទៅ**: បំពានលក្ខខណ្ឌ បញ្ហាសុវត្ថិភាព ឬសកម្មភាពរដ្ឋបាល
- **ដំណោះស្រាយ**: រង់ចាំរហូតដល់ការហាមឃាត់ផុតកំណត់ឬទាក់ទងអ្នកគ្រប់គ្រង

##### AccountKickedOut
- **សារ**: "គណនីត្រូវបានចេញ"
- **ការពិពណ៌នា**: សម័យរបស់អ្នកប្រើប្រាស់ត្រូវបានបញ្ចប់ដោយបង្ខំ
- **មូលហេតុទូទៅ**: អ្នកគ្រប់គ្រងបានចេញអ្នកប្រើប្រាស់ចេញ ការចូលស្របគ្នានៅលើឧបករណ៍ផ្សេង
- **ដំណោះស្រាយ**: អ្នកប្រើប្រាស់ត្រូវតែចូលម្តងទៀត

#### 5. កំហុសសម័យ

##### SessionNotFound
- **សារ**: "រកមិនឃើញសម័យ"
- **ការពិពណ៌នា**: សម័យមិនមានឬត្រូវបានលុប
- **មូលហេតុទូទៅ**: សម័យផុតកំណត់ ត្រូវបានលុបដោយដៃ ឬមិនធ្លាប់ត្រូវបានបង្កើត
- **ដំណោះស្រាយ**: បង្កើតសម័យថ្មីដោយការចូល

---

## Bahasa Melayu (Malay)

### Kategori Ralat

sa-token-rust menyediakan 32 jenis ralat yang diorganisasikan kepada 10 kategori:

#### 1. Ralat Token Asas

##### TokenNotFound
- **Mesej**: "Token tidak dijumpai atau tamat tempoh"
- **Penerangan**: Token yang diminta tidak wujud dalam penyimpanan atau telah tamat tempoh
- **Punca Biasa**: Token tidak pernah dicipta, tamat tempoh secara semulajadi, atau dipadam secara manual
- **Penyelesaian**: Pengguna perlu log masuk semula untuk mendapatkan token baharu

##### InvalidToken
- **Mesej**: "Token tidak sah: {sebab}"
- **Penerangan**: Format atau kandungan token tidak sah
- **Punca Biasa**: Token rosak, diubah suai, atau format salah
- **Penyelesaian**: Sahkan integriti token dan pastikan format betul

##### TokenExpired
- **Mesej**: "Token telah tamat tempoh"
- **Penerangan**: Token telah melepasi masa tamat tempohnya
- **Punca Biasa**: Masa tamat token melebihi tempoh yang dikonfigurasi
- **Penyelesaian**: Gunakan token refresh untuk mendapatkan token akses baharu atau sahkan semula

#### 2. Ralat Pengesahan

##### NotLogin
- **Mesej**: "Pengguna tidak log masuk"
- **Penerangan**: Pengguna cuba mengakses sumber yang dilindungi tanpa pengesahan
- **Punca Biasa**: Tiada token disediakan, token tidak dijumpai dalam permintaan
- **Penyelesaian**: Pengguna mesti log masuk dahulu untuk mendapatkan token yang sah

#### 3. Ralat Kebenaran

##### PermissionDenied
- **Mesej**: "Kebenaran ditolak: tiada kebenaran '{kebenaran}'"
- **Penerangan**: Pengguna tidak mempunyai kebenaran yang diperlukan untuk melakukan tindakan
- **Punca Biasa**: Kebenaran tidak mencukupi yang diberikan kepada pengguna
- **Penyelesaian**: Berikan kebenaran yang diperlukan kepada pengguna atau peranan

##### RoleDenied
- **Mesej**: "Peranan ditolak: tiada peranan '{peranan}'"
- **Penerangan**: Pengguna tidak mempunyai peranan yang diperlukan
- **Punca Biasa**: Pengguna tidak diberikan peranan yang diperlukan
- **Penyelesaian**: Berikan peranan yang diperlukan kepada pengguna

#### 4. Ralat Status Akaun

##### AccountBanned
- **Mesej**: "Akaun disekat sehingga {masa}"
- **Penerangan**: Akaun telah disekat sementara atau kekal
- **Punca Biasa**: Pelanggaran terma, isu keselamatan, atau tindakan pentadbir
- **Penyelesaian**: Tunggu sehingga sekatan tamat atau hubungi pentadbir

##### AccountKickedOut
- **Mesej**: "Akaun ditendang keluar"
- **Penerangan**: Sesi pengguna telah ditamatkan secara paksa
- **Punca Biasa**: Pentadbir menendang pengguna keluar, log masuk serentak pada peranti lain
- **Penyelesaian**: Pengguna perlu log masuk semula

#### 5. Ralat Sesi

##### SessionNotFound
- **Mesej**: "Sesi tidak dijumpai"
- **Penerangan**: Sesi tidak wujud atau telah dipadam
- **Punca Biasa**: Sesi tamat tempoh, dipadam secara manual, atau tidak pernah dicipta
- **Penyelesaian**: Wujudkan sesi baharu dengan log masuk

#### 6. Ralat Nonce

##### NonceAlreadyUsed
- **Mesej**: "Nonce telah digunakan, kemungkinan serangan replay dikesan"
- **Penerangan**: Nonce telah digunakan, menunjukkan kemungkinan serangan replay
- **Punca Biasa**: Permintaan pendua, percubaan serangan replay
- **Penyelesaian**: Jana nonce baharu untuk setiap permintaan

##### InvalidNonceFormat
- **Mesej**: "Format nonce tidak sah"
- **Penerangan**: Nonce tidak mengikut format yang dijangka
- **Punca Biasa**: Nonce rosak, nonce tidak sah yang dibuat secara manual
- **Penyelesaian**: Gunakan kaedah penjanaan nonce standard

##### InvalidNonceTimestamp
- **Mesej**: "Cap waktu nonce tidak sah atau tamat tempoh"
- **Penerangan**: Cap waktu yang tertanam dalam nonce tidak sah atau di luar tetingkap masa yang sah
- **Punca Biasa**: Drift masa sistem, nonce tamat tempoh, atau cap waktu diubah suai
- **Penyelesaian**: Segerakkan masa sistem dan jana nonce baharu

#### 7. Ralat Token Refresh

##### RefreshTokenNotFound
- **Mesej**: "Token refresh tidak dijumpai atau tamat tempoh"
- **Penerangan**: Token refresh tidak wujud atau telah tamat tempoh
- **Punca Biasa**: Tidak pernah dikeluarkan, tamat tempoh, atau dibatalkan
- **Penyelesaian**: Pengguna mesti sahkan semula untuk mendapatkan token refresh baharu

#### 8. Ralat Pengesahan Token

##### TokenEmpty
- **Mesej**: "Token kosong"
- **Penerangan**: Tiada nilai token disediakan
- **Punca Biasa**: String kosong dihantar sebagai token
- **Penyelesaian**: Sediakan nilai token yang sah

##### TokenTooShort
- **Mesej**: "Token terlalu pendek"
- **Penerangan**: Panjang token di bawah minimum yang diperlukan (8 aksara)
- **Punca Biasa**: Token terpotong atau tidak sah
- **Penyelesaian**: Sediakan token lengkap yang sah

#### 9. Ralat OAuth2

##### OAuth2ClientNotFound
- **Mesej**: "Klien OAuth2 tidak dijumpai"
- **Penerangan**: ID klien OAuth2 tidak wujud
- **Punca Biasa**: Klien tidak berdaftar atau ID klien salah
- **Penyelesaian**: Daftarkan klien atau sahkan ID klien

#### 10. Ralat Sistem

##### StorageError
- **Mesej**: "Ralat penyimpanan: {butiran}"
- **Penerangan**: Ralat berlaku semasa mengakses backend penyimpanan
- **Punca Biasa**: Sambungan pangkalan data gagal, Redis tidak tersedia, isu rangkaian
- **Penyelesaian**: Periksa status dan sambungan backend penyimpanan

---

## မြန်မာဘာသာ (Burmese)

### အမှား အမျိုးအစားများ

sa-token-rust သည် အမျိုးအစား 10 ခုခွဲ၍ အမှား အမျိုးအစား 32 မျိုးကို ပံ့ပိုးပေးသည်:

#### 1. အခြေခံ Token အမှားများ

##### TokenNotFound
- **မက်ဆေ့ခ်ျ**: "Token မတွေ့ပါ သို့မဟုတ် သက်တမ်းကုန်သွားပါပြီ"
- **ဖော်ပြချက်**: တောင်းဆိုထားသော Token သည် သိုလှောင်မှုထဲတွင် မရှိပါ သို့မဟုတ် သက်တမ်းကုန်သွားပါပြီ
- **အဖြစ်အများဆုံး အကြောင်းအရင်းများ**: Token ကို ဖန်တီးခဲ့ဖူးခြင်းမရှိခြင်း၊ သဘာဝအတိုင်း သက်တမ်းကုန်ဆုံးခြင်း၊ သို့မဟုတ် လက်ဖြင့် ဖျက်လိုက်ခြင်း
- **ဖြေရှင်းချက်**: အသုံးပြုသူသည် Token အသစ်ရယူရန် ပြန်လည်ဝင်ရောက်ရပါမည်

##### InvalidToken
- **မက်ဆေ့ခ်ျ**: "Token မမှန်ကန်ပါ: {အကြောင်းပြချက်}"
- **ဖော်ပြချက်**: Token ပုံစံ သို့မဟုတ် အကြောင်းအရာ မမှန်ကန်ပါ
- **အဖြစ်အများဆုံး အကြောင်းအရင်းများ**: Token ပျက်စီးခြင်း၊ ပြင်ဆင်ခံရခြင်း၊ သို့မဟုတ် ပုံစံမှားယွင်းခြင်း
- **ဖြေရှင်းချက်**: Token ၏ ပြည့်စုံမှုကို စစ်ဆေးပြီး ပုံစံမှန်ကန်ကြောင်း သေချာပါစေ

##### TokenExpired
- **မက်ဆေ့ခ်ျ**: "Token သက်တမ်းကုန်သွားပါပြီ"
- **ဖော်ပြချက်**: Token သည် ၎င်း၏သက်တမ်းကုန်ဆုံးချိန်ကို ကျော်လွန်သွားပါပြီ
- **အဖြစ်အများဆုံး အကြောင်းအရင်းများ**: Token အချိန်ကုန်ဆုံးမှုသည် ပြင်ဆင်ထားသော ကာလကို ကျော်လွန်သွားခြင်း
- **ဖြေရှင်းချက်**: refresh token ကို အသုံးပြု၍ access token အသစ်ရယူပါ သို့မဟုတ် ပြန်လည်အတည်ပြုပါ

#### 2. အထောက်အထားစိစစ်မှု အမှားများ

##### NotLogin
- **မက်ဆေ့ခ်ျ**: "အသုံးပြုသူ မဝင်ရောက်ရသေးပါ"
- **ဖော်ပြချက်**: အသုံးပြုသူသည် အထောက်အထားစိစစ်မှုမရှိဘဲ ကာကွယ်ထားသော အရင်းအမြစ်ကို ဝင်ရောက်ရန် ကြိုးစားနေသည်
- **အဖြစ်အများဆုံး အကြောင်းအရင်းများ**: Token မပေးထားခြင်း၊ တောင်းဆိုချက်တွင် Token မတွေ့ရှိခြင်း
- **ဖြေရှင်းချက်**: အသုံးပြုသူသည် မှန်ကန်သော Token ရရှိရန် ဦးစွာ ဝင်ရောက်ရမည်

#### 3. ခွင့်ပြုချက် အမှားများ

##### PermissionDenied
- **မက်ဆေ့ခ်ျ**: "ခွင့်ပြုချက် ငြင်းပယ်ခံရသည်: '{ခွင့်ပြုချက်}' ပျောက်ဆုံးနေသည်"
- **ဖော်ပြချက်**: အသုံးပြုသူတွင် လုပ်ဆောင်ချက်ကို လုပ်ဆောင်ရန် လိုအပ်သော ခွင့်ပြုချက် မရှိပါ
- **အဖြစ်အများဆုံး အကြောင်းအရင်းများ**: အသုံးပြုသူအတွက် သတ်မှတ်ထားသော ခွင့်ပြုချက်များ မလုံလောက်ခြင်း
- **ဖြေရှင်းချက်**: အသုံးပြုသူ သို့မဟုတ် အခန်းကဏ္ဍကို လိုအပ်သော ခွင့်ပြုချက် ပေးပါ

##### RoleDenied
- **မက်ဆေ့ခ်ျ**: "အခန်းကဏ္ဍ ငြင်းပယ်ခံရသည်: '{အခန်းကဏ္ဍ}' ပျောက်ဆုံးနေသည်"
- **ဖော်ပြချက်**: အသုံးပြုသူတွင် လိုအပ်သော အခန်းကဏ္ဍ မရှိပါ
- **အဖြစ်အများဆုံး အကြောင်းအရင်းများ**: အသုံးပြုသူကို လိုအပ်သော အခန်းကဏ္ဍ မသတ်မှတ်ထားခြင်း
- **ဖြေရှင်းချက်**: အသုံးပြုသူကို လိုအပ်သော အခန်းကဏ္ဍ သတ်မှတ်ပါ

#### 4. အကောင့် အခြေအနေ အမှားများ

##### AccountBanned
- **မက်ဆေ့ခ်ျ**: "အကောင့်ကို {အချိန်} အထိ ပိတ်ပင်ထားသည်"
- **ဖော်ပြချက်**: အကောင့်ကို ယာယီ သို့မဟုတ် အမြဲတမ်း ပိတ်ပင်ထားသည်
- **အဖြစ်အများဆုံး အကြောင်းအရင်းများ**: စည်းကမ်းများ ချိုးဖောက်ခြင်း၊ လုံခြုံရေး ပြဿနာများ၊ သို့မဟုတ် စီမံခန့်ခွဲသူ၏ လုပ်ဆောင်ချက်
- **ဖြေရှင်းချက်**: ပိတ်ပင်မှု သက်တမ်းကုန်ဆုံးသည့်အထိ စောင့်ဆိုင်းပါ သို့မဟုတ် စီမံခန့်ခွဲသူကို ဆက်သွယ်ပါ

##### AccountKickedOut
- **မက်ဆေ့ခ်ျ**: "အကောင့်ကို ထုတ်ပစ်လိုက်ပါပြီ"
- **ဖော်ပြချက်**: အသုံးပြုသူ၏ session ကို အတင်းအကြပ် ရပ်တန့်လိုက်ပါပြီ
- **အဖြစ်အများဆုံး အကြောင်းအရင်းများ**: စီမံခန့်ခွဲသူက အသုံးပြုသူကို ထုတ်ပစ်ခြင်း၊ အခြား စက်ပစ္စည်းတွင် တစ်ပြိုင်နက် ဝင်ရောက်ခြင်း
- **ဖြေရှင်းချက်**: အသုံးပြုသူသည် ပြန်လည်ဝင်ရောက်ရမည်

#### 5. Session အမှားများ

##### SessionNotFound
- **မက်ဆေ့ခ်ျ**: "Session မတွေ့ပါ"
- **ဖော်ပြချက်**: Session မရှိပါ သို့မဟုတ် ဖျက်လိုက်ပါပြီ
- **အဖြစ်အများဆုံး အကြောင်းအရင်းများ**: Session သက်တမ်းကုန်ခြင်း၊ လက်ဖြင့်ဖျက်ခြင်း၊ သို့မဟုတ် ဖန်တီးခဲ့ဖူးခြင်းမရှိခြင်း
- **ဖြေရှင်းချက်**: ဝင်ရောက်ခြင်းဖြင့် session အသစ် ဖန်တီးပါ

---

## Summary | အကျဉ်းချုပ် | สรุป | Tóm tắt | សង្ខេប | Ringkasan | အကျဉ်းချုပ်

This document provides comprehensive error documentation in 7 languages for sa-token-rust. Each error includes:
- Error message
- Detailed description
- Common causes
- Solutions

For developers integrating sa-token-rust, this guide helps understand and handle errors effectively across different regions and languages.

---

**Version**: 0.1.13  
**Last Updated**: 2025-01-15

