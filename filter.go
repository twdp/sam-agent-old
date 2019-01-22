package sam_agent

import (
	"github.com/astaxie/beego/context"
	"github.com/astaxie/beego/logs"
	"net/http"
	"strconv"
)

const (
	SamUserInfoSessionKey = "__sam_user_info_key__"
	SamTokenCookieName = "__sam_t__"
	SamTokenHeaderName = "token"
)


type UserInfo struct {
	// 用户id
	Id int64

	// 用户名
	UserName string

	// 用户头像
	Avatar string

	// 邮箱  可用于发送验证信息之类的
	Email string

	// 手机号  可用于发送验证信息之类的
	Phone string

	Permissions []*Permission
}



// 查找路径和方法，是否需要登录或验证权限
// 如果需要登录或验证权限，则获取当前用户信息
// nil 则返回401  如果没权限，则返回403
// sam 的过滤器
var SamFilter = func(ctx *context.Context) {
	if SamAgent == nil {
		ctx.Output.SetStatus(http.StatusInternalServerError)
		ctx.ResponseWriter.Write([]byte("系统错误!"))
		panic("sam agent is nil. ")
	}

	var urlStrategy int8 = Anonymous
	var id int64 = 0

	if _id, _strategy, err := a.CheckPermissionStrategy(ctx); err != nil {
		logs.Error("sam filter error: %v", err)
		ctx.ResponseWriter.WriteHeader(http.StatusUnauthorized)
		ctx.ResponseWriter.Write([]byte(err.Error()))
		return
	} else {
		id = _id
		urlStrategy = _strategy
	}

	if urlStrategy == Anonymous {
		return
	}

	var systemInfo *moduleInfo
	if s, err := a.loadSysInfo(); err != nil {
		logs.Error("load system info failed. strategy: Child")
		systemInfo = &moduleInfo{
			keepSign: false,
			permissionType:Child,
			routes:make(map[string][]*tree),
		}
	} else {
		systemInfo = s
	}


		var u *UserInfo

	if uu, ok := ctx.Input.Session(SamUserInfoSessionKey).(*UserInfo); !ok {

		if !systemInfo.keepSign {
			ctx.ResponseWriter.WriteHeader(http.StatusUnauthorized)
			ctx.ResponseWriter.Write([]byte("请重新登录"))
			return
		}
		// 获取token信息
		token := ctx.Input.Header(SamTokenHeaderName)
		if token == "" {
			token = ctx.GetCookie(SamTokenCookieName)
		}

		if token == "" {
			ctx.ResponseWriter.WriteHeader(http.StatusUnauthorized)
			ctx.ResponseWriter.Write([]byte("请重新登录"))
			return
		}
		// 根据token获取用户信息
		if us, err := a.verifyToken(token); err != nil {
			ctx.ResponseWriter.WriteHeader(http.StatusUnauthorized)
			ctx.ResponseWriter.Write([]byte(err.Error()))
			return
		} else {
			u = us
		}
		ctx.Output.Session(SamUserInfoSessionKey, u)
	} else {
		u = uu
	}

	if urlStrategy == OnlyNeedLogin {
		return
	}

	permissionId := ctx.Input.Param("permissionId")
	if permissionId == "" {
		permissionId = ctx.Input.Param(":permissionId")
	}

	var ppId int64 = -1

	if ppid, err := strconv.ParseInt(permissionId, 10, 64); err == nil {
		ppId = ppid
	}

	hasPermission := false


	if u != nil {
		for _, p := range u.Permissions {
			if p.VerifyUrl(ppId, id, systemInfo.permissionType) {
				hasPermission = true
				break
			}
		}
	}

	if !hasPermission {
		// 403没权限
		ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
		ctx.ResponseWriter.Write([]byte("暂无权限"))
	}

}

