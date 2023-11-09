package util

func Ptr2String(s *string) string {
	if s == nil {
		return string("")
	}

	return *s
}
