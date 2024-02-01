package models

type LinePosition struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type ILinePosition interface {
	SetStart(position int)
	SetEnd(position int)
	GetNestedDependencies() map[string]*LinePosition
}

func (line *LinePosition) SetStart(position int) {
	line.Start = position
}
func (line *LinePosition) SetEnd(position int) {
	line.End = position
}
func (line *LinePosition) GetNestedDependencies() map[string]*LinePosition {
	return nil
}
