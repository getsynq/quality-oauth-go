package qualityoauth

import (
	"fmt"
	"os/exec"
	"runtime"
)

// OpenBrowser launches the platform's default browser at url. Windows is
// handled here so every CLI gets it, rather than only the one copy that had it.
func OpenBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		// rundll32 avoids `cmd /c start`, which treats the URL's & as a
		// command separator and needs quoting gymnastics to survive.
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		// xdg-open on Linux and the BSDs; anything else has no convention.
		if path, err := exec.LookPath("xdg-open"); err == nil {
			return exec.Command(path, url).Start()
		}
		return fmt.Errorf("no browser opener found for %s (open the URL manually)", runtime.GOOS)
	}
}
