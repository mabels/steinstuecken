package resolvers

type DNSResult struct {
}

type Resolver interface {
	Resolve(name string) (DNSResult, error)
}

type Action string
const (
	Update = Action("update")
	Remove = Action("remove")
)

type ResultRecordType string
const (
	A = ResultRecordType("A")
	AAAA = ResultRecordType("AAAA")
)

type Result struct {
	Action Action
}

