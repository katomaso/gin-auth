package internal

type stringItem struct {
	Ttl int
	Val string
}

type PerishibleCache struct {
	data map[string]stringItem
	Ttl  int
}

func NewPerishibleCache(tries int) PerishibleCache {
	return PerishibleCache{
		data: make(map[string]stringItem),
		Ttl:  tries,
	}
}

func (c PerishibleCache) Get(key string) (string, bool) {
	if v, exists := c.data[key]; exists {
		if v.Ttl > 0 {
			v.Ttl -= 1
			c.data[key] = v
			return v.Val, true
		} else {
			delete(c.data, key)
		}
	}
	return "", false
}

func (c PerishibleCache) Set(key, val string) {
	c.data[key] = stringItem{Ttl: c.Ttl, Val: val}
}
