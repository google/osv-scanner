package models

type FilePosition struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type IFilePosition interface {
	SetStart(position int)
	SetEnd(position int)
	GetNestedDependencies() map[string]*FilePosition
}

func (p *FilePosition) SetStart(position int) {
	p.Start = position
}
func (p *FilePosition) SetEnd(position int) {
	p.End = position
}
func (p *FilePosition) GetNestedDependencies() map[string]*FilePosition {
	return nil
}
