package sam_agent

// 权限类型
const (
	OnlyOperationPermission = iota
	Equality
	Child
)

const (
	Anonymous = iota
	OnlyNeedLogin
	CheckRolePermission
)

// 系统信息
type SystemInfo struct {

	Id int64

	// 权限类型
	PermissionType int8

	// 是否使用token保持登录
	KeepSign bool

	// 配置在sam中的url列表
	Routers []*Router
}


// url信息
type Router struct {

	// 系统url id
	Id int64

	// url
	Url string

	// method
	Method string

	// url类型
	Type int8
}

type SamAgentFacade interface {

	// 根据appKey 和secret获取系统信息
	LoadSystemInfo(appKey, secret string) (*SystemInfo, error)

	// 验证token
	VerifyToken(appKey, secret, token string) (*UserInfo, error)
}