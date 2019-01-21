package sam_agent

import (
	"encoding/json"
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/astaxie/beego/session"
	"net/http"
	"net/http/httptest"
	"testing"
)

type SamAgentFacadeImpl struct {

}

func (s *SamAgentFacadeImpl) LoadSystemInfo(appKey, secret string) (*SystemInfo, error) {
	return &SystemInfo{
		PermissionType:CheckRolePermission,
		Routers: []*Router{
			{
				1, "/a/1", "POST", CheckRolePermission,
			}, {
				2, "a/d", "POST", CheckRolePermission,
			},
		},
	}, nil
}

func (s *SamAgentFacadeImpl) VerifyToken(token string) (*UserInfo, error) {
	return &UserInfo{
		Id: 1,
		UserName:"1",
		Email:"s",
		Phone: "1",
		P: &Permission{
			PermissionSet: []int64{1,2},
		},
	}, nil
}

func TestAgent_CheckPermissionStrategy(t *testing.T) {
	SamAgent = &SamAgentFacadeImpl{}
	beego.BConfig.WebConfig.Session.SessionOn = true

	ctx := context.NewContext()
	r, _ := http.NewRequest("POST", "/a/d", nil)

	w := httptest.NewRecorder()
	ctx.Reset(w, r)


	config := `{"cookieName":"gosessionid","gclifetime":10, "enableSetCookie":true}`
	conf := new(session.ManagerConfig)
	if err := json.Unmarshal([]byte(config), conf); err != nil {
		t.Fatal("json decode error", err)
	}
	globalSessions, _ :=session.NewManager("memory", conf)
	go globalSessions.GC()
	store, _ := globalSessions.GetSessionStore("ss")
	ctx.Input.CruSession = store
	ctx.SetCookie(SamTokenCookieName, "abc")

	SamFilter(ctx)
	fmt.Println(ctx.Output)
}