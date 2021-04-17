package configs

var CVEs = map[string]map[string]string{
	"redhat": {
		"url": "https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=9999999",
	},
	// "debian": {
	// 	"url": "https://security-tracker.debian.org/tracker/data/json",
	// },
	// "ubuntu": {
	// 	"url": "https://usn.ubuntu.com/usn-db/database-all.json",
	// },
	// "alpine": {
	// 	"url": "https://secdb.alpinelinux.org/v3.10/community.json",
	// },
}

func GetCVEs() map[string]map[string]string {
	return CVEs
}
