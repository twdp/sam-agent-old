package sam_agent

import (
	"github.com/astaxie/beego/logs"
)

const (
	Base int64 = 1
	Position = Base << 6
)

type PermissionMode interface {
	// 需要验证的url
	VerifyUrl(branchId, id int64, url string, method string, sType int8) bool
}


// 按层级的权限
type Permission struct {

	RoleId int64

	RoleName string

	BranchIds []int64

	PermissionSet []int64
}

func (p *Permission) VerifyUrl(branchId, id int64, url string, method string, sType int8) bool {
	if sType != OnlyOperationPermission {
		// 需要验证数据权限
		hasPermission := false
		for _, bId := range p.BranchIds {
			if bId == branchId {
				hasPermission = true
				break
			}
		}
		if !hasPermission {
			logs.Debug("p: %v ,not has branch-id: %d permission", p, branchId)
			return false
		}
	}
	// 验证操作权限
	return p.checkPermission(id)
}

func (p *Permission) checkPermission(id int64) bool {
	// 第多少个int64
	idx := 0
	ii := id
	bitSite := uint(0)

	for true {
		if ii <= 64 {
			bitSite = uint(id ^ (1 << uint(6 * idx))) - 1
			break
		}
		idx++
		ii = ii >> 6
	}
	if len(p.PermissionSet) >= idx {
		permission := p.PermissionSet[idx]
		expect := Base << bitSite
		return permission & expect == expect
	} else {
		return false
	}
}
