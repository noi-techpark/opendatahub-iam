package grants

import (
	"reflect"
	"strings"
	"testing"
)

var rules = Rules{
	Clients:   []string{"timeseries", "content"},
	Inherited: []string{"ODH_ROLE_*"},
}

func TestEffective(t *testing.T) {
	held := Roles{
		"timeseries": {"BDP_A22", "BDP_BLC", "ODH_ROLE_PREMIUM"},
		"content":    {"IDM", "ArticleNOIManager"},
		"realm-mgmt": {"manage-users"},
	}
	cases := map[string]struct {
		grants Grants
		held   Roles
		want   Roles
	}{
		"listed roles only, quota role always carried": {
			Grants{"timeseries": {"BDP_A22"}}, held,
			Roles{"timeseries": {"BDP_A22", "ODH_ROLE_PREMIUM"}},
		},
		"a role the owner lost disappears": {
			Grants{"timeseries": {"BDP_A22", "BDP_CBZ"}}, held,
			Roles{"timeseries": {"BDP_A22", "ODH_ROLE_PREMIUM"}},
		},
		"wildcard follows the owner on that client only": {
			Grants{"content": {All}}, held,
			Roles{"content": {"ArticleNOIManager", "IDM"}, "timeseries": {"ODH_ROLE_PREMIUM"}},
		},
		"empty allow-list still identifies the owner's tier": {
			Grants{}, held,
			Roles{"timeseries": {"ODH_ROLE_PREMIUM"}},
		},
		"clients outside the API list are never carried": {
			Grants{"realm-mgmt": {All}}, held,
			Roles{"timeseries": {"ODH_ROLE_PREMIUM"}},
		},
		"owner without roles": {
			Grants{"timeseries": {All}}, Roles{}, Roles{},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := rules.Effective(tc.grants, tc.held); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	held := Roles{"timeseries": {"BDP_A22", "BDP_BLC", "ODH_ROLE_PREMIUM"}}

	got, err := rules.Normalize(Grants{"timeseries": {"BDP_BLC", "BDP_A22", "BDP_A22", "ODH_ROLE_PREMIUM"}, "content": {}}, held)
	if err != nil {
		t.Fatal(err)
	}
	if want := (Grants{"timeseries": {"BDP_A22", "BDP_BLC"}}); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}

	got, err = rules.Normalize(Grants{"content": {"anything", All}}, held)
	if err != nil {
		t.Fatal(err)
	}
	if want := (Grants{"content": {All}}); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}

	for name, tc := range map[string]struct {
		grants  Grants
		wantErr string
	}{
		"role not held":     {Grants{"timeseries": {"BDP_ADMIN"}}, "do not hold"},
		"unknown client":    {Grants{"realm-management": {All}}, "not an API"},
		"wildcard as a key": {Grants{All: {All}}, "not an API"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := rules.Normalize(tc.grants, held); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want error mentioning %q", err, tc.wantErr)
			}
		})
	}
}
