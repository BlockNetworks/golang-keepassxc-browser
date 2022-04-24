package keepassxc_browser

import "fmt"

type MsgGetDatabasehash struct {
	ActionName string `json:"action"`
	Hash       string `json:"hash"`
	Version    string `json:"version"`
	Success    string `json:"success"`
	Id         string `json:"id"`
	Nonce      string `json:"nonce"`
}

type MsgAssociate struct {
	ActionName string `json:"action"`
	Key        string `json:"key"`
	IdKey      string `json:"idKey"`
	Version    string `json:"version"`
	Success    string `json:"success"`
	Id         string `json:"id"`
	Nonce      string `json:"nonce"`
}

type MsgGeneratePassword struct {
	ActionName string `json:"action"`
	Hash       string `json:"hash"`
	Version    string `json:"version"`
	Success    string `json:"success"`
	Id         string `json:"id"`
	Password   string `json:"password"`
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
	ActionName string       `json:"action"`
	Hash       string       `json:"hash"`
	Version    string       `json:"version"`
	Success    string       `json:"success"`
	Id         string       `json:"id"`
	Url        string       `json:"url"`
	SubmitUrl  string       `json:"submitUrl,omitempty"`
	HttpAuth   string       `json:"httpAuth,omitempty"`
	Keys       []key        `json:"keys"`
	Entries    []LoginEntry `json:"entries"`
	Count      int          `json:"count"`
}

type MsgSetLogin struct {
	ActionName      string       `json:"action"`
	Hash            string       `json:"hash"`
	Version         string       `json:"version"`
	Success         string       `json:"success"`
	Id              string       `json:"id"`
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
	ActionName string `json:"action"`
	Hash       string `json:"hash"`
	Version    string `json:"version"`
	Id         string `json:"id"`
	Nonce      string `json:"nonce"`
	Success    string `json:"success"`
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
	ActionName              string      `json:"action"`
	Id                      string      `json:"id"`
	Nonce                   string      `json:"nonce"`
	Success                 string      `json:"success"`
	DefaultGroup            string      `json:"defaultGroup"`
	DefaultGroupAlwaysAllow bool        `json:"defaultGroupAlwaysAllow"`
	Groups                  GroupsEntry `json:"groups"`
}

type MsgCreateNewGroup struct {
	ActionName string `json:"action"`
	Hash       string `json:"hash"`
	Version    string `json:"version"`
	Id         string `json:"id"`
	Nonce      string `json:"nonce"`
	GroupName  string `json:"groupName"`
	Success    string `json:"success"`
}

type MsgGetTotp struct {
	ActionName string `json:"action"`
	Hash       string `json:"hash"`
	Version    string `json:"version"`
	Id         string `json:"id"`
	Nonce      string `json:"nonce"`
	Totp       string `json:"totp"`
	Uuid       string `json:"uuid"`
	Success    string `json:"success"`
}

func GetMessageType(action string) (ret interface{}, err error) {
	switch action {
	case "change-public-keys":
		return nil, nil
	case "get-databasehash":
		return &MsgGetDatabasehash{ActionName: action}, nil
	case "associate", "test-associate":
		return &MsgAssociate{ActionName: action}, nil
	case "generate-password":
		return &MsgGeneratePassword{ActionName: action}, nil
	case "get-logins":
		return &MsgGetLogins{ActionName: action}, nil
	case "set-login":
		return &MsgSetLogin{ActionName: action}, nil
	case "lock-database", "database-locked":
		return &MsgLockDatabase{ActionName: action}, nil
	case "get-database-groups":
		return &MsgGetDatabaseGroups{ActionName: action}, nil
	case "create-new-group":
		return &MsgCreateNewGroup{ActionName: action}, nil
	case "get-totp":
		return &MsgGetTotp{ActionName: action}, nil
	}

	return nil, fmt.Errorf("Unknown action: %s", action)
}
