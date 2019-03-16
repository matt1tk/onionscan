package deanonymization

import (
	"../config"
	"../report"
	"fmt"
	"net/url"
	"regexp"
)

// ApacheModInfo extracts any information related to exposed mod_info endpoints.
// FIXME: We can make this much smarted than it currently is.
func ApacheModInfo(osreport *report.OnionScanReport, report *report.AnonymityReport, osc *config.OnionScanConfig) {
	modStatus, _ := url.Parse("http://" + osreport.HiddenService + "/server-info")
	id := osreport.Crawls[modStatus.String()]
	crawlRecord, _ := osc.Database.GetCrawlRecord(id)
	if crawlRecord.Page.Status == 200 {
		contents := crawlRecord.Page.Snapshot

		r := regexp.MustCompile(`Server Version: (.*)</dt>`)
		serverVersion := r.FindStringSubmatch(string(contents))

		// Check if this looks like a mod_status page. Sometimes sites simply load their index.
		if len(serverVersion) > 1 {
			osc.LogInfo("Detected Apache mod_info Exposed...\033[091mAlert!\033[0m\n")
			report.FoundApacheModInfo = true

			osc.LogInfo(fmt.Sprintf("\t Using mod_info Server Version: %s\n", serverVersion[1]))

		}
	}
}
