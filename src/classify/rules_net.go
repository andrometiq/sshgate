package classify

import (
	"strings"
)

// curlRule: `curl` is read unless it specifies a write HTTP method,
// carries a request body (-d/--data...), or writes the response body
// to a local file (-o FILE / --output FILE / -O / --remote-name).
// `curl -o -` (stdout) stays read.
func curlRule(args []string) Kind {
	for i, a := range args {
		switch a {
		case "-X", "--request":
			if i+1 < len(args) {
				m := strings.ToUpper(args[i+1])
				if m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH" {
					return KindWrite
				}
			}
		case "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
			"-F", "--form", "-T", "--upload-file":
			return KindWrite
		case "-K", "--config":
			// `-K FILE` reads curl directives from FILE; that file can
			// specify `--output FILE`, `--upload-file`, `-X POST`, etc.
			// The config file is opaque to us. Cited as MAJOR-5 in
			// docs/security-readonly-bypass.md.
			return KindWrite
		case "-o", "--output":
			// `-o FILE` writes to disk; `-o -` is stdout (still read).
			if i+1 < len(args) && args[i+1] != "-" {
				return KindWrite
			}
		case "-O", "--remote-name", "--remote-name-all":
			// `-O` saves to a filename derived from the URL.
			return KindWrite
		case "-D", "--dump-header", "--trace", "--trace-ascii",
			"-c", "--cookie-jar", "--stderr", "--libcurl",
			"--etag-save", "--hsts", "--alt-svc", "--output-dir":
			// curl writes a local FILE in many more modes than -o/-O: the
			// response headers (-D), a full/ascii debug trace (--trace*), the
			// cookie jar (-c), its own stderr (--stderr), generated libcurl
			// C source (--libcurl), the saved ETag (--etag-save), the HSTS
			// cache (--hsts), the Alt-Svc cache (--alt-svc), or the directory
			// that -o/-O targets resolve into (--output-dir). `<flag> -`
			// writes to a stdout/stderr stream (not a disk file) and stays
			// read. The first group found by the 2026-06-14 red-team; the
			// cache-file group (--etag-save/--hsts/--alt-svc/--output-dir) by
			// the 2026-06-15 rig hunt. (Note `-b`/`--cookie` is the INPUT jar
			// — a read — and is intentionally NOT in this set.)
			if i+1 < len(args) && args[i+1] != "-" {
				return KindWrite
			}
		}
		// `=VALUE` long forms of the file-writing flags above.
		for _, pfx := range []string{"--dump-header=", "--trace=", "--trace-ascii=",
			"--cookie-jar=", "--stderr=", "--libcurl=",
			"--etag-save=", "--hsts=", "--alt-svc=", "--output-dir="} {
			if strings.HasPrefix(a, pfx) {
				if strings.TrimPrefix(a, pfx) != "-" {
					return KindWrite
				}
			}
		}
		// Bundled short forms `-DFILE` / `-cFILE` / `-oFILE`. The `-o<path>`
		// glued form (no space) slipped past the exact-token `-o` match above
		// — `curl -o/config/.ssh/authorized_keys URL` classified READ yet
		// curl wrote the file (2026-06-15 rig hunt). `-o-` (stdout) stays
		// read, like the spaced `-o -` form.
		if strings.HasPrefix(a, "-o") && len(a) > 2 && a[1] != '-' {
			if a[2:] != "-" {
				return KindWrite
			}
		}
		if (strings.HasPrefix(a, "-D") || strings.HasPrefix(a, "-c")) && len(a) > 2 {
			if a[2:] != "-" {
				return KindWrite
			}
		}
		if strings.HasPrefix(a, "--data=") || strings.HasPrefix(a, "--data-raw=") ||
			strings.HasPrefix(a, "--data-binary=") || strings.HasPrefix(a, "--data-urlencode=") ||
			strings.HasPrefix(a, "--form=") {
			return KindWrite
		}
		if strings.HasPrefix(a, "--output=") {
			if strings.TrimPrefix(a, "--output=") != "-" {
				return KindWrite
			}
		}
		if strings.HasPrefix(a, "--config=") {
			return KindWrite
		}
		if strings.HasPrefix(a, "-X") && len(a) > 2 {
			m := strings.ToUpper(a[2:])
			if m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH" {
				return KindWrite
			}
		}
	}
	return KindRead
}

// wgetRule: `wget URL` defaults to saving the response to `./URL.tail`
// on disk — that is a write to the local filesystem. Per code-review Mi4
// the read-side form requires explicit stdout output: `-O-` (or its long
// form `--output-document=-`). Anything else — including bare URLs and
// any --post-data / --method=POST/PUT/DELETE/PATCH — is write.
func wgetRule(args []string) Kind {
	stdoutOutput := false
	for i, a := range args {
		switch {
		case a == "-O-", a == "--output-document=-":
			stdoutOutput = true
		case a == "-O", a == "--output-document":
			// Explicit output file: read only if the operand is `-`.
			if i+1 < len(args) && args[i+1] == "-" {
				stdoutOutput = true
			} else {
				return KindWrite
			}
		case strings.HasPrefix(a, "--output-document="):
			// Already handled the "=-" exact case above; any other value
			// names a file and is a write.
			return KindWrite
		case strings.HasPrefix(a, "-O") && len(a) > 2:
			// Combined short flag like `-Ofile` or `-O-`. `-O-` matched
			// the exact-equals case above; `-O<anything>` else is a file.
			return KindWrite
		case a == "-o" || a == "--output-file":
			// `-o FILE` / `--output-file FILE` writes wget's LOG to a file
			// (distinct from `-O`/`--output-document`, the response body) —
			// a local-filesystem write. A `-` operand logs to the stdout
			// stream and stays read; everything else names a file => WRITE.
			// 2026-06-15 rig hunt: `wget -o /tmp/x -O - URL` slipped READ.
			if i+1 >= len(args) || args[i+1] != "-" {
				return KindWrite
			}
		case strings.HasPrefix(a, "--output-file="):
			// Already excluded the `=-` stream form here.
			if strings.TrimPrefix(a, "--output-file=") != "-" {
				return KindWrite
			}
		case strings.HasPrefix(a, "-o") && len(a) > 2:
			// Combined short flag `-o<path>` (glued log file). `-o-` is the
			// stdout stream and stays read; `-o<anything>` else is a file.
			if a[2:] != "-" {
				return KindWrite
			}
		case a == "--post-data", strings.HasPrefix(a, "--post-data="),
			a == "--post-file", strings.HasPrefix(a, "--post-file="):
			return KindWrite
		}
		if strings.HasPrefix(a, "--method=") {
			m := strings.ToUpper(strings.TrimPrefix(a, "--method="))
			if m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH" {
				return KindWrite
			}
		}
		// Bundled short-flag run reaching -O (output-document). `-qO-`, `-nvO-`
		// send the response BODY to stdout (READ-eligible); `-qOfile` names a
		// file (WRITE). A value-consuming short flag before O swallows the rest
		// of the bundle as its value, so stop there — an O after it is data, and
		// the body still downloads to a file (the function's final WRITE
		// default). Value-taking wget short flags (per wget(1)):
		// o a i B t T w Q l A R D P e U  (O itself handled by the switch). The
		// guard a[1] != 'O' avoids double-handling the standalone/glued `-O…`
		// forms; a[1] != 'o' keeps the lowercase log-file flag out (a[1]=='o'
		// is in the stop-list so the scan breaks without setting stdoutOutput,
		// leaving the body downloading to a file → correct WRITE default).
		if len(a) >= 3 && a[0] == '-' && a[1] != '-' && a[1] != 'O' {
			for j := 1; j < len(a); j++ {
				c := a[j]
				if c == 'O' {
					val := a[j+1:] // remainder of THIS arg is -O's value
					switch {
					case val == "-":
						stdoutOutput = true // -…O-  → body to stdout (read-eligible)
					case val != "":
						return KindWrite // -…O<file> → names a file
					default: // O is last in the bundle; value is the NEXT arg
						if i+1 < len(args) && args[i+1] == "-" {
							stdoutOutput = true
						} else {
							return KindWrite
						}
					}
					break
				}
				if strings.IndexByte("oaiBtTwQlARDPeU", c) >= 0 {
					break // value-consuming flag: rest of bundle is its value
				}
			}
		}
	}
	if stdoutOutput {
		return KindRead
	}
	return KindWrite
}
