use ntex::web::HttpRequest;
use sa_token_core::token::TokenValue;

/// 中文: 必填 Token 提取器，从请求扩展读取 Token，若不存在返回 None
/// English: Required token extractor, reads token from request extensions, returns None when missing
#[derive(Clone)]
pub struct SaTokenExtractor(pub Option<TokenValue>);

impl SaTokenExtractor {
    /// 中文: 中间件会在扩展中写入 TokenValue，这里负责取出
    /// English: Middleware stores TokenValue in extensions; this method retrieves it
    pub fn from_request(req: &HttpRequest) -> Self {
        let token = req.extensions().get::<TokenValue>().cloned();
        SaTokenExtractor(token)
    }
}

/// 中文: 可选 Token 提取器，用于无需强制登录的路由
/// English: Optional token extractor for routes where login is not required
#[derive(Clone)]
pub struct OptionalSaTokenExtractor(pub Option<TokenValue>);

impl OptionalSaTokenExtractor {
    /// 中文: 读取扩展中的 TokenValue，可能为 None
    /// English: Reads TokenValue from extensions, possibly None
    pub fn from_request(req: &HttpRequest) -> Self {
        let token = req.extensions().get::<TokenValue>().cloned();
        OptionalSaTokenExtractor(token)
    }
}

/// 中文: 登录 ID 提取器，映射为 Option<String>
/// English: Login ID extractor returning Option<String>
#[derive(Clone)]
pub struct LoginIdExtractor(pub Option<String>);

impl LoginIdExtractor {
    /// 中文: 若中间件已经写入 login_id，则返回 Some；否则 None
    /// English: Returns Some when middleware stored login_id; otherwise None
    pub fn from_request(req: &HttpRequest) -> Self {
        let id = req.extensions().get::<String>().cloned();
        LoginIdExtractor(id)
    }
}

