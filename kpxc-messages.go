package keepassxc_browser

type action struct {
	Action string `json:"action"`
}

type key struct {
	Id  string `json:"id"`
	Key string `json:"key"`
}

type MsgGetDatabasehash struct {
	action
}

type MsgAssociate struct {
	action
	Key   string `json:"key"`
	IdKey string `json:"idKey"`
}

type MsgTestAssociate struct {
	action
	key
}

type MsgGetLogins struct {
	action
	Url       string `json:"url"`
	SubmitUrl string `json:"submitUrl,omitempty"`
	HttpAuth  string `json:"httpAuth,omitempty"`
	Keys      []key  `json:"keys"`
}

type MsgSetLogin struct {
	action
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

type MsgLockDatabase struct {
	action
}

type MsgGetDatabaseGroups struct {
	action
}

type MsgCreateNewGroup struct {
	action
	GroupName string `json:"groupName"`
}

type MsgGetTotp struct {
	action
	Uuid string `json:"uuid"`
}

type MsgRequestAutotype struct {
	action
	Search string `json:"search"`
}
