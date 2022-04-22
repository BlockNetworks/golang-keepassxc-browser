package keepassxc_browser

type Action struct {
	ActionName string `json:"action"`
}

type MsgBase struct {
	Action
	Hash    string `json:"hash"`
	Version string `json:"version"`
	Success string `json:"success"`
	Id      string `json:"id"`
	Nonce   string `json:"nonce"`
}

type MsgPublicKey struct {
	PubKey string `json:"publicKey"`
}

type MsgReqGetDatabasehash struct {
	Action
}

type MsgResGetDatabasehash struct {
	MsgBase
}

type MsgReqAssociate struct {
	Action
	Key   string `json:"key"`
	IdKey string `json:"idKey"`
}

type MsgResAssociate struct {
	MsgBase
}

type MsgReqTestAssociate struct {
	Action
	Id  string `json:"id"`
	Key string `json:"key"`
}

type MsgResTestAssociate struct {
	MsgBase
}

type MsgReqGeneratePassword struct {
	Action
}

type MsgResGeneratePassword struct {
	MsgBase
	Password string `json:"password"`
}

type key struct {
	Id  string `json:"id"`
	Key string `json:"key"`
}

type MsgReqGetLogins struct {
	Action
	Url       string `json:"url"`
	SubmitUrl string `json:"submitUrl,omitempty"`
	HttpAuth  string `json:"httpAuth,omitempty"`
	Keys      []key  `json:"keys"`
}

type LoginEntry struct {
	Login        string              `json:"login"`
	Name         string              `json:"name"`
	Password     string              `json:"password"`
	Expired      string              `json:"expired,omitempty"`
	Uuid         string              `json:"uuid"`
	StringFields []map[string]string `json:"stringFields"`
}

type MsgResGetLogins struct {
	MsgBase
	Entries []LoginEntry `json:"entries"`
	Count   int          `json:"count"`
}

type MsgReqSetLogin struct {
	Action
	Url             string `json:"url"`
	SubmitUrl       string `json:"submitUrl"`
	Id              string `json:"id"`
	Nonce           string `json:"nonce"`
	Login           string `json:"login"`
	Password        string `json:"password"`
	Group           string `json:"group"`
	GroupUuid       string `json:"groupUuid"`
	Uuid            string `json:"uuid"`
	DownloadFavicon bool   `json:"downloadFavicon"`
}

type MsgReqLockDatabase struct {
	Action
}

type MsgResLockDatabase struct {
	Action
}

type MsgReqGetDatabaseGroups struct {
	Action
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

type MsgResGetDatabaseGroups struct {
	MsgBase
	DefaultGroup            string      `json:"defaultGroup"`
	DefaultGroupAlwaysAllow bool        `json:"defaultGroupAlwaysAllow"`
	Groups                  GroupsEntry `json:"groups"`
}

type MsgReqCreateNewGroup struct {
	Action
	GroupName string `json:"groupName"`
}

type MsgResCreateNewGroup struct {
	MsgBase
	GroupEntry
}

type MsgGetTotp struct {
	Action
	Uuid string `json:"uuid"`
}

type MsgRequestAutotype struct {
	Action
	Search string `json:"search"`
}
