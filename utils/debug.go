package utils

import "os"

func InDebugMode() bool {
	return os.Getenv("VULDB_DEBUG") != ""
}
