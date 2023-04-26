package iptables_actions

type StringArrayBuilder struct {
	Out []string
}

func NewStringArrayBuilder() *StringArrayBuilder {
	return &StringArrayBuilder{}
}

func (sab *StringArrayBuilder) Add(strs ...string) *StringArrayBuilder {
	sab.Out = append(sab.Out, strs...)
	return sab
}
