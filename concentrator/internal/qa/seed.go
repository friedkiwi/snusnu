package qa

import (
	"context"
	"fmt"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type Account struct{ Email, Username, Password, Role, NetID string }
type Router struct {
	OwnerEmail, Name, Token, CP string
	LLCFacing                   bool
}

var Accounts = []Account{
	{"admin@qa.snusnu.test", "qa_admin", "qa-admin-password-123", "admin", "QAADMIN"},
	{"alice@qa.snusnu.test", "qa_alice", "qa-alice-password-123", "user", "QAALICE"},
	{"bob@qa.snusnu.test", "qa_bob", "qa-bob-password-123", "user", "QABOB"},
}
var Routers = []Router{
	{"alice@qa.snusnu.test", "Alice V4R4", "qa-alice-router-token-1234567890", "SNAA", true},
	{"bob@qa.snusnu.test", "Bob V5R4", "qa-bob-router-token-1234567890", "SNAB", false},
}

const AdminAPIToken = "qa-admin-api-token-1234567890"

// Seed is used only on a newly created QA database. It never reads DB env vars.
func Seed(ctx context.Context, db *store.Store) error {
	owners := map[string]string{}
	for _, account := range Accounts {
		id := store.RandomUUID()
		hash, err := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		_, err = db.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at,remind_after,username,netid) VALUES(?,?,?,?,?,?,?,?)", id, account.Email, string(hash), account.Role, store.Now(), store.Now()+30*24*3600, account.Username, account.NetID)
		if err != nil {
			return fmt.Errorf("seed user %s: %w", account.Email, err)
		}
		owners[account.Email] = id
	}
	for _, router := range Routers {
		id := store.RandomUUID()
		owner := owners[router.OwnerEmail]
		_, err := db.Exec(ctx, "INSERT INTO routers(id,owner_id,display_name,llc_facing,created_at) VALUES(?,?,?,?,?)", id, owner, router.Name, router.LLCFacing, store.Now())
		if err != nil {
			return err
		}
		_, err = db.Exec(ctx, "INSERT INTO router_credentials(id,router_id,secret_hash,created_at) VALUES(?,?,?,?)", store.RandomUUID(), id, store.Hash(router.Token), store.Now())
		if err != nil {
			return err
		}
	}
	_, err := db.Exec(ctx, "INSERT INTO api_clients(id,user_id,name,secret_hash,created_at) VALUES(?,?,?,?,?)", store.RandomUUID(), owners[Accounts[0].Email], "QA admin API", store.Hash(AdminAPIToken), store.Now())
	return err
}
