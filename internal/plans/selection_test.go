package plans

import (
	"errors"
	"reflect"
	"testing"
)

func TestToggleSelectionExplainsPrerequisitesAndDependents(t *testing.T) {
	p := validPlan()
	selected, err := ToggleSelection(p, nil, "primary", true)
	if err != nil || !reflect.DeepEqual(selected.Selected, []string{"address", "interface", "primary"}) || !reflect.DeepEqual(selected.Added, selected.Selected) || len(selected.Removed) != 0 {
		t.Fatalf("select: %+v %v", selected, err)
	}
	removed, err := ToggleSelection(p, selected.Selected, "interface", false)
	if err != nil || len(removed.Selected) != 0 || !reflect.DeepEqual(removed.Removed, selected.Selected) || len(removed.Added) != 0 {
		t.Fatalf("deselect: %+v %v", removed, err)
	}
	only, err := ToggleSelection(p, selected.Selected, "primary", false)
	if err != nil || !reflect.DeepEqual(only.Selected, []string{"address", "interface"}) || !reflect.DeepEqual(only.Removed, []string{"primary"}) {
		t.Fatalf("deselect leaf: %+v %v", only, err)
	}
	if _, err = ToggleSelection(p, []string{"primary"}, "address", true); !errors.Is(err, ErrDependency) {
		t.Fatalf("accepted invalid original: %v", err)
	}
	if _, err = ToggleSelection(p, nil, "not-found", true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted unknown action: %v", err)
	}
}

func TestExistingPrimaryCannotAliasUnrelatedCreate(t *testing.T) {
	p := validPlan()
	p.Actions[2].ExistingIPID = 123
	p.Actions[2].Dependencies = nil
	if err := Validate(p); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ambiguous existing IP accepted: %v", err)
	}
}
