package sam_agent

import (
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/cache"
	"github.com/astaxie/beego/context"
	"github.com/astaxie/beego/logs"
	cache2 "github.com/goburrow/cache"
	"github.com/hprose/hprose-golang/rpc"
	"strings"
	"sync"
	"tianwei.pro/beego-guava"
	"time"
)


var SamAgent SamAgentFacade

var a *agent

func init() {
	samServers := beego.AppConfig.DefaultString("samServers", "none")
	if samServers == "none" {
		// 本地连接
	} else {
		address := strings.Split(samServers, ",")
		client := rpc.NewClient(address...)
		client.UseService(&SamAgent)
	}
	appKey := beego.AppConfig.String("appKey")
	if appKey == "" {
		logs.Warn("app key is empty")
	}
	secret := beego.AppConfig.String("secret")
	if secret == "" {
		logs.Warn("secret is empty")
	}
	a = &agent{
		cacheManager: make(map[string]cache.Cache),
		appKey: appKey,
		secret: secret,
	}
}

type tree struct {
	beego.Tree
	id int64
	Type int8
}



type moduleInfo struct {
	routes map[string][]*tree
	permissionType int8
	keepSign bool
}

type agent struct {
	sync.Mutex

	appKey string
	secret string

	//systemInfo *SystemInfo

	cacheManager map[string]cache.Cache
}

func (a *agent) loadCacheByKey(key string) cache.Cache {
	if c, exist := a.cacheManager[key]; exist {
		return c
	} else {
		a.Lock()
		defer a.Unlock()
		if v, ok := a.cacheManager[key]; ok {
			return v
		}

		c := cache2.NewLoadingCache(func(key cache2.Key) (value cache2.Value, e error) {
			return nil, nil
		}, cache2.WithMaximumSize(1000),
			cache2.WithExpireAfterAccess(30 * time.Minute),)
		cc := beego_guava.NewGuava(c)
		a.cacheManager[key] = cc
		return cc
	}
}

const (
	tokenKey = "_token_"
	systemInfo = "_system_info_"
)

func (a *agent) verifyToken(token string) (*UserInfo, error) {
	a.checkAgent()
	cache := a.loadCacheByKey(tokenKey)
	if cache.IsExist(token) {
		return cache.Get(token).(*UserInfo), nil
	} else {
		if u, err := SamAgent.VerifyToken(a.appKey, a.secret, token); err != nil {
			return u, err
		} else {
			cache.Put(token, u, time.Minute)
			return u, nil
		}
	}
}

func (a *agent) checkAgent() {
	if SamAgent == nil {
		panic("sam agent is nil.")
	}
}
func (a *agent) loadSysInfo() (*moduleInfo, error) {
	a.checkAgent()
	cache := a.loadCacheByKey(systemInfo)
	if cache.IsExist("---") {
		return cache.Get("---").(*moduleInfo), nil
	} else {
		if s, err := SamAgent.LoadSystemInfo(a.appKey, a.secret); err != nil {
			return nil, err
		} else {
			routes := make(map[string][]*tree)
			for k := range beego.HTTPMETHOD  {
				routes[k] = []*tree{}
			}

			for _, v := range s.Routers {
				tt := beego.NewTree()
				tt.AddRouter(v.Url, "sam")
				t := &tree{
					Tree: *tt,
					id: v.Id,
					Type: v.Type,
				}
				routes[v.Method] = append(routes[v.Method], t)
			}
			ss := &moduleInfo{
				permissionType: s.PermissionType,
				keepSign: s.KeepSign,
				routes: routes,
			}

			cache.Put("---", ss, time.Minute)
			return ss, nil
		}
	}
}

// beego.HTTPMETHOD
//
// @return int64  id
// @return string 正则表达的url
// @return string   method
// @return strategy Anonymous\OnlyNeedLogin\CheckRolePermission
// @return error  -> 验证时报错
func (a *agent) CheckPermissionStrategy(ctx *context.Context) (int64, int8, error) {
	method := ctx.Input.Method()
	path := ctx.Input.URL()

	if s, err := a.loadSysInfo(); err != nil {
		return 0, CheckRolePermission, err
	} else {
		var tree *tree
		routers := s.routes[method]
		for _, r := range routers {
			obj := r.Match(path, ctx)
			if obj != nil && obj.(string) == "sam" {
				tree = r
				break
			}
		}
		if tree == nil {
			return 0, Anonymous, nil
		}

		return tree.id, tree.Type, nil
	}


}


