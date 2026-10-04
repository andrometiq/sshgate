package confine

// These exact cases belong to later migration lanes. Remove each entry when migrated.
var pendingMigration = mergePending(pendingM1, pendingM2, pendingM3)

func mergePending(parts ...map[string]string) map[string]string {
	merged := map[string]string{}
	for _, part := range parts {
		for name, reason := range part {
			merged[name] = reason
		}
	}
	return merged
}
