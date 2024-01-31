package models

type FilePosition struct {
	Line int `json:"line"`
}

type LinePosition struct {
	Start FilePosition `json:"start"`
	End   FilePosition `json:"end"`
}

type ILinePosition interface {
	SetStart(position FilePosition)
	SetEnd(position FilePosition)
	GetNestedDependencies() map[string]*LinePosition
}

func (line *LinePosition) SetStart(position FilePosition) {
	line.Start = position
}
func (line *LinePosition) SetEnd(position FilePosition) {
	line.End = position
}
func (line *LinePosition) GetNestedDependencies() map[string]*LinePosition {
	return nil
}
