package osvdev

import "fmt"

type ErrDuringPaging struct {
	PageDepth int
	Inner     error
}

func (e *ErrDuringPaging) Error() string {
	return fmt.Sprintf("error during paging at depths %d - %s", e.PageDepth, e.Inner)
}

func (e *ErrDuringPaging) Unwrap() error {
	return e.Inner
}
