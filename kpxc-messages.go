package keepassxc_browser

type Action struct {
	ActionName string `json:"action"`
}

type MsgPublicKey struct {
	PubKey string `json:"publicKey"`
}

type MsgGetDatabasehash struct {
	Action
}

type MsgReqAssociate struct {
	BaseRequest
	Key   string `json:"key"`
	IdKey string `json:"idKey"`
}

type MsgResAssociate struct {
	BaseResponse
	Hash    string `json:"hash"`
	Version string `json:"version"`
	Success string `json:"success"`
	Id      string `json:"id"`
	Nonce   string `json:"nonce"`
}

type MsgReqTestAssociate struct {
	BaseRequest
	Id  string `json:"id"`
	Key string `json:"key"`
}

type MsgReqGeneratePassword struct {
	BaseRequest
	Nonce     string `json:"nonce"`
	ClientId  string `json:"clientID"`
	RequestId string `json:"requestID,omitempty"`
}

type MsgResGeneratePassword struct {
	Action
	Password string `json:"password"`
	Version  string `json:"version"`
	Success  string `json:"success"`
	Nonce    string `json:"nonce"`
}

type key struct {
	Id  string `json:"id"`
	Key string `json:"key"`
}

type MsgReqGetLogins struct {
	BaseRequest
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
	BaseResponse
	Entries []LoginEntry `json:"entries"`
	Count   int          `json:"count"`
	Hash    string       `json:"hash"`
	Version string       `json:"version"`
	Success string       `json:"success"`
	Nonce   string       `json:"nonce"`
}

type MsgSetLogin struct {
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

type MsgLockDatabase struct {
	Action
}

type MsgGetDatabaseGroups struct {
	Action
}

type MsgCreateNewGroup struct {
	Action
	GroupName string `json:"groupName"`
}

type MsgGetTotp struct {
	Action
	Uuid string `json:"uuid"`
}

type MsgRequestAutotype struct {
	Action
	Search string `json:"search"`
}
