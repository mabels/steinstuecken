package config

type SsnConfigClient struct {
	CertFile    string
	KeyFile     string
	UpStreamUrl string
	bufferSize  int
}

func (c *SsnConfigClient) BufferSize() int {
	if c.bufferSize == 0 {
		return 4096
	}
	return c.bufferSize
}

type SsnConfigServer struct {
	CertFile string
	KeyFile  string
	Addr     string
}

type SsnConfig struct {
	Client SsnConfigClient
	Server SsnConfigServer
}

type SsnConfigEndpoint struct {
}
