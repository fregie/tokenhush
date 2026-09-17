package fixturepkg

// Greeting is a tiny exported struct used as a parser fixture.
type Greeting struct {
	Text string
}

// Hello returns a greeting for name.
func Hello(name string) Greeting {
	return Greeting{Text: "hello, " + name}
}
