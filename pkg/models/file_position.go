package models

type Position struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type FilePosition struct {
	Line     Position `json:"line"`
	Column   Position `json:"column"`
	Filename string   `json:"file_name"`
}

type IFilePosition interface {
	SetLineStart(position int)
	SetColumnStart(position int)
	SetLineEnd(position int)
	SetColumnEnd(position int)
	GetNestedDependencies() map[string]*FilePosition
}

func (p *FilePosition) SetLineStart(position int) {
	p.Line.Start = position
}
func (p *FilePosition) SetColumnStart(position int) {
	p.Column.Start = position
}
func (p *FilePosition) SetLineEnd(position int) {
	p.Line.End = position
}
func (p *FilePosition) SetColumnEnd(position int) {
	p.Column.End = position
}
func (p *FilePosition) GetNestedDependencies() map[string]*FilePosition {
	return nil
}

func (p *FilePosition) IsStartSet() bool {
	return p.Line.Start != 0 && p.Column.Start != 0
}
