package models

type IDAliases struct {
	ID      string
	Aliases []string
}

func (c *Vulnerability) ToIDAliases() IDAliases {
	return IDAliases{
		ID:      c.ID,
		Aliases: c.Aliases,
	}
}

func ConvertToIDAliases(c []Vulnerability) []IDAliases {
	output := []IDAliases{}
	for _, v := range c {
		output = append(output, v.ToIDAliases())
	}
	return output
}
