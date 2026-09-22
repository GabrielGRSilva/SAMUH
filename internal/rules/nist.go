// Package rules - nist.go provides the NIST CSF 2.0 catalog with
// detailed descriptions for each function and its categories.
package rules

// NISTInfo contains details about a NIST CSF 2.0 function.
type NISTInfo struct {
	// ID is the short identifier (e.g., "GV").
	ID string

	// Name is the human-readable function name.
	Name string

	// Description explains what the function covers.
	Description string

	// URL links to the NIST CSF documentation.
	URL string

	// Categories lists the category identifiers within this function.
	Categories []string
}

// NISTCatalog maps each NIST CSF 2.0 function to its detailed information.
var NISTCatalog = map[NISTFunction]NISTInfo{
	NISTGovern: {
		ID:          "GV",
		Name:        "Govern",
		Description: "The organization's cybersecurity risk management strategy, expectations, and policy are established, communicated, and monitored.",
		URL:         "https://www.nist.gov/cyberframework",
		Categories:  []string{"GV.OC", "GV.RM", "GV.RR", "GV.PO", "GV.OV", "GV.SC"},
	},
	NISTIdentify: {
		ID:          "ID",
		Name:        "Identify",
		Description: "The organization's current cybersecurity risk is understood.",
		URL:         "https://www.nist.gov/cyberframework",
		Categories:  []string{"ID.AM", "ID.RA", "ID.IM"},
	},
	NISTProtect: {
		ID:          "PR",
		Name:        "Protect",
		Description: "Safeguards to manage the organization's cybersecurity risk are used.",
		URL:         "https://www.nist.gov/cyberframework",
		Categories:  []string{"PR.AA", "PR.AT", "PR.DS", "PR.PS", "PR.IR"},
	},
	NISTDetect: {
		ID:          "DE",
		Name:        "Detect",
		Description: "Possible cybersecurity attacks and compromises are found and analyzed.",
		URL:         "https://www.nist.gov/cyberframework",
		Categories:  []string{"DE.CM", "DE.AE"},
	},
	NISTRespond: {
		ID:          "RS",
		Name:        "Respond",
		Description: "Actions regarding a detected cybersecurity incident are taken.",
		URL:         "https://www.nist.gov/cyberframework",
		Categories:  []string{"RS.MA", "RS.AN", "RS.CO", "RS.MI"},
	},
	NISTRecover: {
		ID:          "RC",
		Name:        "Recover",
		Description: "Assets and operations affected by a cybersecurity incident are restored.",
		URL:         "https://www.nist.gov/cyberframework",
		Categories:  []string{"RC.RP", "RC.CO"},
	},
}
