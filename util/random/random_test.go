package random

import (
	"fmt"
	"testing"
)

func TestRandomIntRange(t *testing.T) {
	fmt.Println(RandomIntRange(10000, 60000))
}
