package config

type SsnConfigClient struct {
	CertFile    string
	KeyFile     string
	UpStreamUrl string
}

type SsnConfig struct {
	Client SsnConfigClient
}

type SsnConfigEndpoint struct {
}
