package msgs

type InitMFAAuth struct {
	RedirectUri string `json:"ruri"`
	TimeSigned  int64  `json:"time"`
	Nonce       string `json:"nonce"`
}
