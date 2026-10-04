package confine

// Pending cases owned by migration lane M2. Remove each entry when migrated.
var pendingM2 = map[string]string{
	"L-ASYNC-OWNER":      "legacy registered leg; migration lane owns its proof conversion",
	"L-ASYNC-SCOPE":      "legacy registered leg; migration lane owns its proof conversion",
	"L-CRASH-LOWER-PIPE": "legacy registered leg; migration lane owns its proof conversion",
	"L-CRASH-NO-HELPER":  "legacy registered leg; migration lane owns its proof conversion",
	"L-LIFECYCLE":        "legacy registered leg; migration lane owns its proof conversion",
	"L-PROCESS-MRELEASE": "legacy registered leg; migration lane owns its proof conversion",
	"L-RETUNE":           "legacy registered leg; migration lane owns its proof conversion",
	"L-RETUNE-SETPARAM":  "legacy registered leg; migration lane owns its proof conversion",
	"L-SCHED-USER":       "legacy registered leg; migration lane owns its proof conversion",
	"L-SESSION":          "legacy registered leg; migration lane owns its proof conversion",
	"L-SIGNAL-HOST":      "legacy registered leg; migration lane owns its proof conversion",
	"L-SIGNAL-OWN-GROUP": "legacy registered leg; migration lane owns its proof conversion",
	"L-SIGNAL-SCOPE":     "legacy registered leg; migration lane owns its proof conversion",
	"U-AsyncOwner":       "legacy registered leg; migration lane owns its proof conversion",
	"U-Mrelease":         "legacy registered leg; migration lane owns its proof conversion",
	"U-Retune":           "legacy registered leg; migration lane owns its proof conversion",
	"U-Signal":           "legacy registered leg; migration lane owns its proof conversion",
}
