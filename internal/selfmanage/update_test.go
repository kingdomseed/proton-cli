package selfmanage

import "testing"

func TestSelfUpdateStaysDisabledWithoutSignedChecksums(t *testing.T) {
	if SignedUpdatesEnabled {
		t.Fatal("self-update must stay disabled until checksum signatures are verified")
	}
}

func TestAssetName(t *testing.T) {
	cases := []struct {
		goos, goarch string
		want         string
		wantErr      bool
	}{
		{"linux", "amd64", "proton-cli_linux_amd64", false},
		{"linux", "arm64", "proton-cli_linux_arm64", false},
		{"darwin", "amd64", "proton-cli_darwin_amd64", false},
		{"darwin", "arm64", "proton-cli_darwin_arm64", false},
		{"windows", "amd64", "proton-cli_windows_amd64.exe", false},
		{"windows", "arm64", "", true},
		{"freebsd", "amd64", "", true},
		{"linux", "386", "", true},
	}
	for _, tc := range cases {
		got, err := AssetName(tc.goos, tc.goarch)
		if tc.wantErr {
			if err == nil {
				t.Errorf("AssetName(%q, %q) = %q, want error", tc.goos, tc.goarch, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("AssetName(%q, %q) unexpected error: %v", tc.goos, tc.goarch, err)
			continue
		}
		if got != tc.want {
			t.Errorf("AssetName(%q, %q) = %q, want %q", tc.goos, tc.goarch, got, tc.want)
		}
	}
}

func TestExpectedChecksum(t *testing.T) {
	sums := []byte(
		"584cfd0f2c2a55caf23dd5a3559824dfd2d94659c0431a54b2063c05c5a7357d  proton-cli_1.9.11_linux_amd64.tar.gz\n" +
			"6324962556a4e9337c617499be20f3c5595689d4274ddbec3ab24471cc3cc767  proton-cli_linux_amd64\n" +
			"9831812b643fd772bd6fd9cc4981627d8e317f1ca53e791deb679845f7f0346a  proton-cli_windows_amd64.exe\n")

	got, err := ExpectedChecksum(sums, "proton-cli_linux_amd64")
	if err != nil {
		t.Fatalf("ExpectedChecksum: %v", err)
	}
	if want := "6324962556a4e9337c617499be20f3c5595689d4274ddbec3ab24471cc3cc767"; got != want {
		t.Errorf("ExpectedChecksum = %q, want %q", got, want)
	}

	if _, err := ExpectedChecksum(sums, "proton-cli_darwin_arm64"); err == nil {
		t.Error("ExpectedChecksum for missing asset: want error, got nil")
	}
}

func TestIsNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"1.9.12", "1.9.11", true},
		{"1.9.11", "1.9.11", false},
		{"1.9.10", "1.9.11", false},
		{"v2.0.0", "1.9.11", true},
		{"1.10.0", "1.9.11", true},
		{"1.9.11", "dev", true},
		{"garbage", "1.9.11", false},
	}
	for _, tc := range cases {
		if got := IsNewer(tc.latest, tc.current); got != tc.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v", tc.latest, tc.current, got, tc.want)
		}
	}
}
