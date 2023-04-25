package iptables_actions

type stringArrayBuilder struct {
	out []string
}

func newStringArrayBuilder() *stringArrayBuilder {
	return &stringArrayBuilder{}
}

func (sab *stringArrayBuilder) add(strs ...string) *stringArrayBuilder {
	sab.out = append(sab.out, strs...)
	return sab
}
