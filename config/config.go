package config

type Configurations struct {
	Server ServerConfigurations
}
type ServerConfigurations struct {
	Url      string
	Username string
	Password string
}
