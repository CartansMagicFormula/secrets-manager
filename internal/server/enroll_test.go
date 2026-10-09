package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentRotatesStartToken(t *testing.T) {
	hs := newHarness(t)
	hs.initAndLogin()
	rec := hs.do("POST", "/v1/admin/clients", `{"name":"svc","policies":["svc"]}`, nil)
	first, id := decode(t, rec)["token"].(string), decode(t, rec)["client"].(map[string]any)["id"].(string)
	enroll := func(code string) (int, string) {
		rec := hs.do("POST", "/v1/auth/enroll", "", map[string]string{"Authorization": "Bearer " + code})
		if rec.Code != 200 {
			return rec.Code, ""
		}
		return rec.Code, decode(t, rec)["token"].(string)
	}

	out := decode(t, hs.do("POST", "/v1/admin/clients/"+id+"/enroll", "", nil))
	code := out["code"].(string)
	if !strings.HasPrefix(code, enrollPrefix) || out["client"] != "svc" {
		t.Fatalf("enroll code: %v", out)
	}
	status, second := enroll(code)
	if status != 200 || !strings.HasPrefix(second, tokenPrefix) || second == first {
		t.Fatalf("exchange: %d", status)
	}
	if status, _ := enroll(code); status != 401 {
		t.Fatal("enrollment code used twice")
	}
	// New token works; the previous one keeps working during the grace period only
	hs.clientLogin(second, "svc-1")
	hs.clientLogin(first, "svc-2")
	hs.now = hs.now.Add(25 * time.Hour)
	if hs.do("POST", "/v1/auth/login", `{"instance":"svc-2"}`, map[string]string{"Authorization": "Bearer " + first}).Code != 401 {
		t.Fatal("previous start token valid after the grace period")
	}
	hs.clientLogin(second, "svc-1")

	// Codes expire after 15 minutes and end with sealing
	hs.login()
	code = decode(t, hs.do("POST", "/v1/admin/clients/"+id+"/enroll", "", nil))["code"].(string)
	hs.now = hs.now.Add(16 * time.Minute)
	if status, _ := enroll(code); status != 401 {
		t.Fatal("expired enrollment code accepted")
	}
	hs.login()
	code = decode(t, hs.do("POST", "/v1/admin/clients/"+id+"/enroll", "", nil))["code"].(string)
	if hs.do("POST", "/v1/admin/clients/nope/enroll", "", nil).Code != 404 {
		t.Fatal("enrollment for unknown client")
	}
	// A second code replaces the first (one open code per client)
	code2 := decode(t, hs.do("POST", "/v1/admin/clients/"+id+"/enroll", "", nil))["code"].(string)
	if status, _ := enroll(code); status != 401 {
		t.Fatal("replaced code still valid")
	}
	if status, _ := enroll(code2); status != 200 {
		t.Fatal("current code refused")
	}
	// Revoked clients cannot be enrolled
	hs.do("DELETE", "/v1/admin/clients/"+id, "", nil)
	if hs.do("POST", "/v1/admin/clients/"+id+"/enroll", "", nil).Code != 404 {
		t.Fatal("revoked client enrolled")
	}
}

func TestEnrollmentCodesEndWithSeal(t *testing.T) {
	hs := newHarness(t)
	master := hs.initAndLogin()
	id := decode(t, hs.do("POST", "/v1/admin/clients", `{"name":"svc","policies":["svc"]}`, nil))["client"].(map[string]any)["id"].(string)
	code := decode(t, hs.do("POST", "/v1/admin/clients/"+id+"/enroll", "", nil))["code"].(string)
	hs.do("POST", "/v1/sys/seal", "", nil)
	hs.do("POST", "/v1/sys/unseal", `{"master_key":"`+master+`"}`, nil)
	if hs.do("POST", "/v1/auth/enroll", "", map[string]string{"Authorization": "Bearer " + code}).Code != 401 {
		t.Fatal("enrollment code survived sealing")
	}
}

const devList = `{
  "environment": "dev",
  "secrets": [
    {"path": "lumen/db-app-password", "kind": "generated", "length": 32},
    {"path": "lumen/llm-gateway-token", "kind": "generated"},
    {"path": "llm-gateway/anthropic", "kind": "static", "note": "commander enters it in the UI"}
  ],
  "clients": [
    {"name": "lumen-api", "policies": ["lumen"]},
    {"name": "lumen-postgres-certs", "policies": [], "pki_names": ["postgres", "lumen-postgres-1"]}
  ]
}`

func TestApplyClientList(t *testing.T) {
	hs := newHarness(t)
	hs.initAndLogin()
	hs.do("POST", "/v1/admin/clients", `{"name":"old-service","policies":["old"]}`, nil)

	if rec := hs.do("POST", "/v1/admin/apply", strings.Replace(devList, `"dev"`, `"production"`, 1), nil); rec.Code != 422 {
		t.Fatalf("list for another environment applied: %d", rec.Code)
	}
	rec := hs.do("POST", "/v1/admin/apply", devList, nil)
	if rec.Code != 200 {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	var report applyReport
	_ = json.Unmarshal(rec.Body.Bytes(), &report)
	if len(report.CreatedClients) != 2 || len(report.CreatedSecrets) != 2 || len(report.MissingStatic) != 1 ||
		len(report.NotInList) != 1 || report.NotInList[0] != "old-service" {
		t.Fatalf("report: %+v", report)
	}
	// Generated values stay in the vault: not in the report, but readable by the client
	var secrets []map[string]any
	_ = json.Unmarshal(hs.do("GET", "/v1/admin/secrets", "", nil).Body.Bytes(), &secrets)
	if len(secrets) != 2 || secrets[0]["length"] != float64(32) {
		t.Fatalf("secrets: %v", secrets)
	}

	// Idempotent; a changed policy is updated, nothing deleted
	rec = hs.do("POST", "/v1/admin/apply", devList, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &report)
	if len(report.CreatedClients) != 0 || len(report.CreatedSecrets) != 0 || report.UnchangedClients != 2 {
		t.Fatalf("second apply: %+v", report)
	}
	changed := strings.Replace(devList, `"policies": ["lumen"]`, `"policies": ["lumen", "shared"]`, 1)
	_ = json.Unmarshal(hs.do("POST", "/v1/admin/apply", changed, nil).Body.Bytes(), &report)
	if len(report.UpdatedClients) != 1 || report.UpdatedClients[0] != "lumen-api" {
		t.Fatalf("update: %+v", report)
	}

	// New clients have no usable start token until enrolled
	var clients []map[string]any
	_ = json.Unmarshal(hs.do("GET", "/v1/admin/clients", "", nil).Body.Bytes(), &clients)
	var id string
	for _, c := range clients {
		if c["name"] == "lumen-api" {
			id = c["id"].(string)
		}
	}
	code := decode(t, hs.do("POST", "/v1/admin/clients/"+id+"/enroll", "", nil))["code"].(string)
	start := decode(t, hs.do("POST", "/v1/auth/enroll", "", map[string]string{"Authorization": "Bearer " + code}))["token"].(string)
	access := hs.clientLogin(start, "lumen-api-1")
	got := decode(t, hs.do("GET", "/v1/secrets/lumen/db-app-password", "", map[string]string{"Authorization": "Bearer " + access}))
	if len(got["value"].(string)) != 32 {
		t.Fatalf("generated secret: %v", got)
	}

	bad := []string{
		`{"environment":"dev","secrets":[{"path":"../x","kind":"generated"}],"clients":[]}`,
		`{"environment":"dev","secrets":[{"path":"a/b","kind":"magic"}],"clients":[]}`,
		`{"environment":"dev","secrets":[],"clients":[{"name":"x y","policies":["a"]}]}`,
		`{"environment":"dev","secrets":[],"clients":[{"name":"svc","policies":[]}]}`,
		`{"environment":"dev","secrets":[],"clients":[{"name":"svc","policies":["a"]},{"name":"svc","policies":["b"]}]}`,
		`{"environment":"dev","secrets":[],"clients":[],"extra":1}`,
	}
	for _, body := range bad {
		if code := hs.do("POST", "/v1/admin/apply", body, nil).Code; code < 400 {
			t.Errorf("accepted: %s", body)
		}
	}
}

func TestEnvironmentSetting(t *testing.T) {
	if _, err := New(Config{DataDir: t.TempDir(), Environment: "prod"}); err == nil {
		t.Fatal("unknown environment accepted")
	}
	hs := newHarness(t)
	if decode(t, hs.do("GET", "/v1/sys/status", "", nil))["environment"] != "dev" {
		t.Fatal("environment not reported")
	}
}
