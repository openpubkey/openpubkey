package msgs

type InitMFAAuth struct {
	Issuer      string `json:"iss"`
	RedirectUri string `json:"ruri"`
	TimeSigned  int64  `json:"time"`
	Nonce       string `json:"nonce"`
}
