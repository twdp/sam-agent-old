package sam_agent

import (
	"fmt"
	"testing"
)

func TestPermission_VerifyUrl(t *testing.T) {

}

func TestPermission_checkPermission(t *testing.T) {
	p := &Permission{
		PermissionSet: []int64{
			// 1, 65, 66, 67, 190
			1, 7,62,
		},
	}
	fmt.Println(p.checkPermission(1))
	fmt.Println(p.checkPermission(65))
	fmt.Println(p.checkPermission(66))
	fmt.Println(p.checkPermission(67))
	if !p.checkPermission(1) {
		t.Fatal("p check permission 1 failed.")
	}

	if !p.checkPermission(67) {
		t.Fatal("p check permission 67 failed.")
	}

	if p.checkPermission(68) {
		t.Fatal("p check permission 68 failed.")
	}
	if !p.checkPermission(190) {
		t.Fatal("p check permission 190 failed.")
	}

}