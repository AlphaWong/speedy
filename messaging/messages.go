package messaging

type Message struct {
	URL         string `json:"url"`
	CallbackURL string `json:"callback_url"`
	TimeoutSec  int32  `json:"timeout_sec"`
	AuthToken   string `json:"auth_token"`
}
