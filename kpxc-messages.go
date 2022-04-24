package keepassxc_browser

import "fmt"

type MsgI interface {
	IsSuccess() bool
}

type MsgBase struct {
	ActionName string `json:"action"`
	Hash       string `json:"hash"`
	Version    string `json:"version"`
	Success    string `json:"success"`
	Id         string `json:"id"`
	Nonce      string `json:"nonce"`
}

func (m *MsgBase) IsSuccess() bool {
	return m.Success == "true"
}

type MsgGetDatabasehash struct {
	MsgBase
}

type MsgAssociate struct {
	MsgBase
	Key   string `json:"key"`
	IdKey string `json:"idKey"`
}

type MsgGeneratePassword struct {
	MsgBase
	Password string `json:"password"`
}

type key struct {
	Id  string `json:"id"`
	Key string `json:"key"`
}

type LoginEntry struct {
	Login        string              `json:"login"`
	Name         string              `json:"name"`
	Password     string              `json:"password"`
	Expired      string              `json:"expired,omitempty"`
	Uuid         string              `json:"uuid"`
	StringFields []map[string]string `json:"stringFields"`
}

type MsgGetLogins struct {
	MsgBase
	Url       string       `json:"url"`
	SubmitUrl string       `json:"submitUrl,omitempty"`
	HttpAuth  string       `json:"httpAuth,omitempty"`
	Keys      []key        `json:"keys"`
	Entries   []LoginEntry `json:"entries"`
	Count     int          `json:"count"`
}

type MsgSetLogin struct {
	MsgBase
	Url             string       `json:"url"`
	SubmitUrl       string       `json:"submitUrl"`
	Login           string       `json:"login"`
	Password        string       `json:"password"`
	Group           string       `json:"group"`
	GroupUuid       string       `json:"groupUuid"`
	Uuid            string       `json:"uuid"`
	DownloadFavicon bool         `json:"downloadFavicon"`
	Entries         []LoginEntry `json:"entries"`
	Count           int          `json:"count"`
}

type MsgLockDatabase struct {
	MsgBase
}

type GroupEntry struct {
	Name string `json:"name"`
	Uuid string `json:"uuid"`
}

type GroupChild struct {
	GroupEntry
	Children []GroupChild `json:"children"`
}

type GroupsEntry struct {
	Groups []GroupChild `json:"groups"`
}

type MsgGetDatabaseGroups struct {
	MsgBase
	DefaultGroup            string      `json:"defaultGroup"`
	DefaultGroupAlwaysAllow bool        `json:"defaultGroupAlwaysAllow"`
	Groups                  GroupsEntry `json:"groups"`
}

type MsgCreateNewGroup struct {
	MsgBase
	GroupName string `json:"groupName"`
}

type MsgGetTotp struct {
	MsgBase
	Totp string `json:"totp"`
	Uuid string `json:"uuid"`
}

func GetMessageType(action string) (ret MsgI, err error) {
	switch action {
	case "change-public-keys":
		return nil, nil
	case "get-databasehash":
		return &MsgGetDatabasehash{MsgBase: MsgBase{ActionName: action}}, nil
	case "associate", "test-associate":
		return &MsgAssociate{MsgBase: MsgBase{ActionName: action}}, nil
	case "generate-password":
		return &MsgGeneratePassword{MsgBase: MsgBase{ActionName: action}}, nil
	case "get-logins":
		return &MsgGetLogins{MsgBase: MsgBase{ActionName: action}}, nil
	case "set-login":
		return &MsgSetLogin{MsgBase: MsgBase{ActionName: action}}, nil
	case "lock-database", "database-locked":
		return &MsgLockDatabase{MsgBase: MsgBase{ActionName: action}}, nil
	case "get-database-groups":
		return &MsgGetDatabaseGroups{MsgBase: MsgBase{ActionName: action}}, nil
	case "create-new-group":
		return &MsgCreateNewGroup{MsgBase: MsgBase{ActionName: action}}, nil
	case "get-totp":
		return &MsgGetTotp{MsgBase: MsgBase{ActionName: action}}, nil
	}

	return nil, fmt.Errorf("Unknown action: %s", action)
}
