package deanonymization

import (
	"../config"
	"../report"
	"fmt"
	"net/url"
	"regexp"
)

var phpInfoArr = [3]string{"/phpinfo.php", "/info.php", "/php.php"}

// Check if phpinfo.php is visible
func PhpInfo(osreport *report.OnionScanReport, report *report.AnonymityReport, osc *config.OnionScanConfig) {

	for _, infoFile := range phpInfoArr {
		phpInfo, _ := url.Parse("http://" + osreport.HiddenService + infoFile)
		id := osreport.Crawls[phpInfo.String()]
		crawlRecord, _ := osc.Database.GetCrawlRecord(id)
		if crawlRecord.Page.Status == 200 {
			contents := crawlRecord.Page.Snapshot

			r := regexp.MustCompile(`PHP Version (.*)`)
			phpVersion := r.FindStringSubmatch(string(contents))

			// Check if this looks like a mod_status page. Sometimes sites simply load their index.
			if len(phpVersion) > 1 {
				osc.LogInfo("Detected PHPInfo Exposed...\033[091mAlert!\033[0m\n")
				report.PhpInfoFiles = append(report.PhpInfoFiles, infoFile)

				osc.LogInfo(fmt.Sprintf("\t Using PHP version: %s\n", phpVersion[1]))

			}
		}
	}

}
