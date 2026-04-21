package monitor

import (
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// shallowClone fetches only the tip of the given branch (depth=1) into
// targetDir. A shallow clone avoids pulling the full history, which keeps
// the temp-directory small and the scan fast.
//
// The cloneURL must contain embedded credentials; it is used in-process by
// go-git and is never written to disk or printed.
func shallowClone(cloneURL, branch, targetDir string) error {
	_, err := gogit.PlainClone(targetDir, false, &gogit.CloneOptions{
		URL:           cloneURL,
		ReferenceName: plumbing.NewBranchReferenceName(branch),
		SingleBranch:  true,
		Depth:         1,
		NoCheckout:    false,
	})
	return err
}
