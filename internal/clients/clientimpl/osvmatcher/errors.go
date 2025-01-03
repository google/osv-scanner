package osvmatcher

import "fmt"

type DuringPagingError struct {
	PageDepth int
	Inner     error
}

func (e *DuringPagingError) Error() string {
	return fmt.Sprintf("error during paging at depths %d - %s", e.PageDepth, e.Inner)
}

func (e *DuringPagingError) Unwrap() error {
	return e.Inner
}
