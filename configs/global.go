package configs

var CVEs = map[string]map[string]string{
	"redhat": {
		"url": "https://access.redhat.com/hydra/rest/securitydata/cve.json?page={1}",
	},
	"alpine": {
		"url": "https://secdb.alpinelinux.org/v3.10/community.json",
	},
}

func GetCVEs() map[string]map[string]string {
	return CVEs
}
