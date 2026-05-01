// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import "testing"

func TestSelfTestRuns(t *testing.T) {
	if err := runSelfTest(); err != nil {
		t.Fatal(err)
	}
}
