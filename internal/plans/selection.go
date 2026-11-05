package plans

import "sort"

// SelectionChange describes a checkbox operation before any approval is saved.
// Added and Removed include all affected actions, so an operator can see when a
// prerequisite or dependent changes. It is not an approval or authorization.
type SelectionChange struct {
	Selected []string `json:"selected"`
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
}

// ToggleSelection returns a dependency-closed selection. Selecting an action
// adds its prerequisites; deselecting one removes every dependent transitively.
// Empty selections are allowed for editing, but cannot be approved/digested.
func ToggleSelection(p Plan, current []string, actionID string, checked bool) (SelectionChange, error) {
	if err := Validate(p); err != nil {
		return SelectionChange{}, err
	}
	if len(current) > 0 {
		if err := ValidateSelection(p, current); err != nil {
			return SelectionChange{}, err
		}
	}
	byID := make(map[string]Action, len(p.Actions))
	for _, action := range p.Actions {
		byID[action.ID] = action
	}
	if _, ok := byID[actionID]; !ok {
		return SelectionChange{}, ErrInvalid
	}
	old := make(map[string]bool, len(current))
	for _, id := range current {
		old[id] = true
	}
	chosen := make(map[string]bool, len(current))
	for _, id := range current {
		chosen[id] = true
	}
	if checked {
		var include func(string)
		include = func(id string) {
			if chosen[id] {
				return
			}
			chosen[id] = true
			for _, dep := range byID[id].Dependencies {
				include(dep)
			}
		}
		include(actionID)
	} else {
		delete(chosen, actionID)
		// Iterate to a fixed point: any action whose dependency is absent must
		// be removed, including actions indirectly depending on the target.
		for changed := true; changed; {
			changed = false
			for id := range chosen {
				for _, dep := range byID[id].Dependencies {
					if !chosen[dep] {
						delete(chosen, id)
						changed = true
						break
					}
				}
			}
		}
	}
	out := SelectionChange{Selected: []string{}, Added: []string{}, Removed: []string{}}
	for id := range chosen {
		out.Selected = append(out.Selected, id)
		if !old[id] {
			out.Added = append(out.Added, id)
		}
	}
	for id := range old {
		if !chosen[id] {
			out.Removed = append(out.Removed, id)
		}
	}
	sort.Strings(out.Selected)
	sort.Strings(out.Added)
	sort.Strings(out.Removed)
	return out, nil
}
